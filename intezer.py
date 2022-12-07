# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import concurrent.futures
import hashlib
import http
import itertools
import json
import sys
from collections import defaultdict
from datetime import date
from datetime import datetime
import logging
import os
import time
import typing
from urllib.parse import urljoin
import contextlib

from volatility3.cli import text_renderer
from volatility3.framework import exceptions, interfaces, renderers, automagic, plugins
from volatility3.framework.configuration import requirements
from volatility3.plugins.windows import info, pslist, envars, dlllist, cmdline, malfind

import requests
import requests.adapters
import tenacity

vollog = logging.getLogger(__name__)
API_VERSION = 'v2-0'

END_REASONS = {
    'DONE': 'done',
    'INTERRUPTED': 'interrupted',
    'FAILED': 'failed'
}

SCAN_TYPE_MEMORY_DUMP_ANALYSIS = 'memory_dump_analysis'

HEADER_SIZE = 0x400


def is_pe_header(data):
    return data[:2] == b'MZ'


def json_serial(obj):
    """JSON serializer for objects not serializable by default json code.
    See: https://stackoverflow.com/questions/11875770/how-to-overcome-datetime-datetime-not-json-serializable"""

    if isinstance(obj, (datetime, date)):
        return obj.isoformat()

    if isinstance(obj, renderers.format_hints.HexBytes):
        return text_renderer.hex_bytes_as_text(obj)

    if isinstance(obj, interfaces.renderers.Disassembly):
        return text_renderer.display_disassembly(obj)

    if isinstance(obj, interfaces.renderers.BaseAbsentValue):
        return None

    raise TypeError("Type %s not serializable" % type(obj))


class IntezerProxy(contextlib.AbstractContextManager):
    """Proxy for accessing the Intezer API"""

    def __init__(self, base_url, api_key):
        self.base_url = base_url
        self.api_key = api_key
        self._session: typing.Optional[requests.Session] = None
        self.scan_id = None
        self.endpoint_analysis_id = None

        self.api_url = urljoin(base_url, '/api')
        self.scans_url = urljoin(base_url, '/scans')

    def __enter__(self):
        self._session = requests.session()
        self._session.mount('https://', requests.adapters.HTTPAdapter(max_retries=3))
        self._session.mount('http://', requests.adapters.HTTPAdapter(max_retries=3))
        self._session.headers = {'User-Agent': 'volatility_plugin/{}'.format('{}.{}.{}'.format(*Intezer._version))}
        return self

    def __exit__(self, *exc_details):
        if self._session:
            self._session.close()
        return False

    def init_access_token(self):
        if 'Authorization' not in self._session.headers:
            response = requests.post(f'{self.api_url}/{API_VERSION}/get-access-token', json={'api_key': self.api_key})

            if response.status_code == http.HTTPStatus.UNAUTHORIZED:
                vollog.error('Invalid Intezer API key')

            response.raise_for_status()
            access_token = response.json()['result']
            self._session.headers['Authorization'] = f'Bearer {access_token}'

    @tenacity.retry(retry=tenacity.retry_if_exception_type(requests.exceptions.RequestException),
                    stop=tenacity.stop_after_attempt(2),
                    reraise=True)
    def _post(self, url_path, **kwargs):
        self.init_access_token()
        response = self._session.post(url_path, **kwargs)
        return response

    def start_scan(self, host_info):
        data = {'start_time': time.time(),
                'scanner_info': {
                    'image_type': host_info['image_type'],
                    'process_path': '',
                    'username': 'N/A'
                },
                'options': {'analyze': True},
                'scan_type': SCAN_TYPE_MEMORY_DUMP_ANALYSIS}

        response = self._post(f'{self.api_url}/scans', json=data)

        if response.status_code == http.HTTPStatus.FORBIDDEN:
            vollog.error("Memory scan isn't available for user or no available quota. "
                         "Contact support@intezer.com for assistance")

        response.raise_for_status()

        self.scan_id = response.json()['result']['scan_id']
        self.endpoint_analysis_id = response.json()['result']['analysis_id']

    def send_host_info(self, system_type, profile, computer_name):
        host_info = {'host_info': {'system_type': system_type,
                                   'profile': profile,
                                   'computer_name': computer_name}
                     }
        response = self._post(f'{self.scans_url}/scans/{self.scan_id}/host-info', json=host_info)
        response.raise_for_status()

    def send_processes_info(self, ps_list):
        response = self._post(
            f'{self.scans_url}/scans/{self.scan_id}/processes-info',
            json={'processes_info': ps_list})
        response.raise_for_status()

    def send_loaded_modules_info(self, pid, loaded_modules_list):
        response = self._post(f'{self.scans_url}/scans/{self.scan_id}/processes/{pid}/loaded-modules-info',
                              json={'loaded_modules_info': loaded_modules_list})
        response.raise_for_status()

    def send_injected_modules_info(self, injected_module_list):
        response = self._post(f'{self.scans_url}/scans/{self.scan_id}/injected-modules-info',
                              json={'injected_modules_info': injected_module_list})
        response.raise_for_status()

    def send_memory_module_dumps_info(self, memory_modules_info):
        response = self._post(f'{self.scans_url}/scans/{self.scan_id}/memory-module-dumps-info',
                              json={'memory_module_dumps_info': memory_modules_info})
        response.raise_for_status()
        return response.json()['result']

    def upload_collected_binaries(self, dump_file_path, collected_from):
        with open(dump_file_path, 'rb') as file_to_upload:
            response = self._post(f'{self.scans_url}/scans/{self.scan_id}/{collected_from}/collected-binaries',
                                  headers={'Content-Type': 'application/octet-stream'},
                                  data=file_to_upload)
            response.raise_for_status()

    def end_scan(self, end_reason):
        response = self._post(f'{self.scans_url}/scans/{self.scan_id}/end',
                              json={'end_time': time.time(), 'reason': end_reason})
        response.raise_for_status()
        if end_reason == END_REASONS['DONE']:
            vollog.info(
                'Analysis sent successfully, You can see your analysis at: '
                '{}/endpoint-analyses/{}'.format(self.base_url, self.endpoint_analysis_id))


class Intezer(interfaces.plugins.PluginInterface):
    """
    Analyzes all code in a windows memory image using Intezer.

    Examples:
        python3 vol.py -f [memdump] -o [output-dir] -v windows.intezer.Intezer --intezer-key [api-key]
    """

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 2)

    @classmethod
    def get_requirements(cls) -> typing.List[interfaces.configuration.RequirementInterface]:
        # Since we're calling the plugin, make sure we have the plugin's requirements
        return [
            requirements.ModuleRequirement(name='kernel', description='Windows kernel',
                                           architectures=["Intel32", "Intel64"]),
            requirements.VersionRequirement(name='pslist', component=pslist.PsList, version=(2, 0, 0)),
            requirements.VersionRequirement(name='info', component=info.Info, version=(1, 0, 0)),
            requirements.VersionRequirement(name='envars', component=envars.Envars, version=(1, 0, 0)),
            requirements.VersionRequirement(name='dlllist', component=dlllist.DllList, version=(2, 0, 0)),
            requirements.VersionRequirement(name='cmdline', component=cmdline.CmdLine, version=(1, 0, 0)),
            requirements.VersionRequirement(name='malfind', component=malfind.Malfind, version=(0, 0, 0)),
            requirements.StringRequirement(name='intezer-key',
                                           description="Intezer API key"),
            requirements.URIRequirement(name='intezer-instance-url',
                                        description="URL of the Intezer instance for self hosted instances",
                                        default='https://analyze.intezer.com',
                                        optional=True),
            requirements.ListRequirement(name='pid',
                                         element_type=int,
                                         description='Process IDs to include (all other processes are excluded)',
                                         optional=True),
            requirements.IntRequirement(name='max-file-size',
                                        description='Max file size to send to upload to Intezer in MB',
                                        default=50,
                                        optional=True)
        ]

    def _get_intezer_api_key(self):
        api_key = self.config.get('intezer-key') or os.getenv('INTEZER_API_KEY')

        if not api_key:
            raise ValueError(
                'Missing Intezer API key. Use "{}" parameter, or store it as an environment variable at "{}".'.format(
                    'intezer-key', 'INTEZER_API_KEY'))

        return api_key

    def _get_output_dir(self) -> typing.AnyStr:
        """Getting the output directory of the dumped files. The output dir isn't accessible by default, so we're using
        a hack, where we write a temp file, and use the file handle to get its path"""
        temp_filename = 'intezer-temp.txt'
        file_handle = self.open(temp_filename)
        output_dir = os.path.dirname(file_handle._name)
        file_handle.close()

        full_temp_file_path = os.path.join(output_dir, file_handle.preferred_filename)
        if os.path.isfile(full_temp_file_path):
            try:
                os.remove(full_temp_file_path)
            except Exception:
                vollog.warning('Error removing the temp file', exc_info=True)

        return output_dir

    def _run_volatility_command_and_get_info(
            self,
            plugin_class: typing.Type[interfaces.plugins.PluginInterface],
            output_dir: str,
            enable_dump=False,
            add_pid=True,
            use_cache=True) -> \
            typing.List[typing.Dict[typing.AnyStr, typing.Any]]:

        result = None

        pid_string = '.'.join(self.config.get('pid')) if self.config.get('pid') else 'all'

        cache_filename = f'intezer-cache-{plugin_class.__name__}-{pid_string}.json'
        cache_file_path = os.path.join(output_dir, cache_filename)

        # trying to load from cache
        if use_cache:
            if os.path.isfile(cache_file_path):
                vollog.info(f'Loading {cache_filename} result from cache')
                with open(cache_file_path, 'r') as f:
                    result = json.load(f)

        if not result:
            vollog.info(f'Running plugin {plugin_class.__name__}')
            automagics = automagic.choose_automagic(automagic.available(self._context), plugin_class)
            plugin = plugins.construct_plugin(self.context, automagics, plugin_class, self.config_path,
                                              self._progress_callback, self.open)

            plugin.config['dump'] = enable_dump

            if add_pid:
                plugin.config['pid'] = self.config.get('pid')

            treegrid = plugin.run()
            rows = []

            def visitor(item_node: renderers.TreeNode, _):
                rows.append(item_node.values)

            treegrid.populate(visitor)

            column_names = [c.name for c in treegrid.columns]
            result = [dict(zip(column_names, row)) for row in rows]

            # storing in cache
            if use_cache:
                json_result = json.dumps(result, default=json_serial)

                with open(cache_file_path, 'w') as f:
                    f.write(json_result)

        return result

    def _get_env_vars_info(self, output_dir: str):
        env_vars = self._run_volatility_command_and_get_info(envars.Envars, output_dir, add_pid=False)

        computer_name = None
        username_by_pid = dict()

        for env_row in env_vars:
            var_name = env_row['Variable']
            var_value = env_row['Value']

            if var_name == 'COMPUTERNAME' and not computer_name:
                computer_name = var_value
                continue

            if var_name == 'USERNAME' and 'PID' in env_row:
                username_by_pid[int(env_row['PID'])] = var_value

        return computer_name, username_by_pid

    def _get_image_info(self, output_dir: str):
        info_records = self._run_volatility_command_and_get_info(info.Info, output_dir, add_pid=False)
        image_info = {}
        for record in info_records:
            if record['Variable'] == 'Is64Bit':
                image_info['image_type'] = str(64 if bool(record['Value']) else 32)

            elif record['Variable'] == 'Symbols':
                # to create a readable symbol, starting after 'volatility3/' and ending after '.pdb'
                symbol_name = ''.join(record['Value'].split('volatility3/')[-1].partition('.pdb')[:2])
                image_info['symbols'] = symbol_name

        return image_info

    def _get_processes(self, username_by_pid: dict, dll_by_pid: dict) -> dict:
        filter_func = pslist.PsList.create_pid_filter(self.config.get('pid', None))
        kernel = self.context.modules[self.config['kernel']]
        processes = pslist.PsList.list_processes(context=self.context,
                                                 layer_name=kernel.layer_name,
                                                 symbol_table=kernel.symbol_table_name,
                                                 filter_func=filter_func)
        processes_info = dict()
        for proc in processes:
            pid = proc.UniqueProcessId

            try:
                cmdline_ = cmdline.CmdLine.get_cmdline(self.context, kernel.symbol_table_name, proc)
            except exceptions.InvalidAddressException:
                cmdline_ = None

            process_path = 'N/A'
            if dll_by_pid.get(pid):
                process_path = dll_by_pid[pid][0]['Path']

            # setting mandatory fields
            proc_info = dict(pid=pid,
                             ppid=proc.InheritedFromUniqueProcessId,
                             process_path=process_path,
                             image_type=str(32 if proc.get_is_wow64() else 64))

            # setting optional fields

            if cmdline_:
                proc_info['command_line'] = cmdline_

            if username_by_pid.get(pid):
                proc_info['username'] = username_by_pid.get(pid)

            if isinstance(proc.get_create_time(), datetime):
                proc_info['start_time'] = proc.get_create_time().timestamp()
            else:
                proc_info['start_time'] = time.time()

            processes_info[pid] = proc_info

        return processes_info

    @staticmethod
    def _extract_dump_info(output_dir, file_output, header_hash_set) -> \
            typing.Tuple[typing.Optional[str], typing.Optional[str], typing.Optional[str], typing.Optional[int]]:
        dump_file_path = os.path.join(output_dir, file_output)

        if not os.path.isfile(dump_file_path):
            vollog.warning(f"Dump file isn't found {dump_file_path}")
            return None, None, None, None

        with open(dump_file_path, 'rb') as f:
            data = f.read()
            header_hash = hashlib.sha256(data[:HEADER_SIZE]).hexdigest()
            sha256, file_size = None, None
            if header_hash not in header_hash_set:
                header_hash_set.add(header_hash)
                sha256 = hashlib.sha256(data).hexdigest()
                file_size = len(data)

        return dump_file_path, header_hash, sha256, file_size

    @staticmethod
    def _populate_record_with_file_info(
            output_dir, file_output, sha256_by_header_hash, dll_or_malfind_record, malfind=True) -> bool:
        dump_file_path = os.path.join(output_dir, file_output)
        is_new_header = False

        if not os.path.isfile(dump_file_path):
            vollog.warning(f"Dump file isn't found {dump_file_path}")
            return is_new_header

        with open(dump_file_path, 'rb') as f:
            data = f.read()
            is_headerless = not is_pe_header(data)
            file_size = len(data)
            header_hash = hashlib.sha256(data[:HEADER_SIZE]).hexdigest()

            # it's not the first time we see this header, we can use the sha256 already calculated
            if header_hash in sha256_by_header_hash:
                sha256 = sha256_by_header_hash[header_hash]
            else:  # it's the first time we see this header
                sha256 = hashlib.sha256(data).hexdigest()
                sha256_by_header_hash[header_hash] = sha256
                is_new_header = True

        dll_or_malfind_record['sha256'] = sha256
        dll_or_malfind_record['size'] = file_size
        dll_or_malfind_record['dump_file_path'] = dump_file_path
        dll_or_malfind_record['is_headerless'] = is_headerless

        if malfind:
            dll_or_malfind_record['dump_method'] = 'fileless' if is_headerless else 'raw'

        return is_new_header

    @staticmethod
    def organize_dump_files_by_sha256(dll_list, malfind_list, output_dir):
        """Organizing dump file paths by sha256"""
        sha256_by_header_hash = dict()
        dll_dump_file_path_by_sha256 = dict()
        headerless_dump_file_path_by_sha256 = dict()
        injected_module_dump_file_path_by_sha256 = dict()

        for dll_record in dll_list:
            file_output = dll_record['File output']

            if file_output == 'Error outputting file':
                vollog.debug('Error dumping file {}, {}'.format(
                    dll_record.get('PID'), dll_record.get('Base')))
                continue

            is_new_header = Intezer._populate_record_with_file_info(
                output_dir, file_output, sha256_by_header_hash, dll_record)

            if is_new_header:
                if not dll_record['is_headerless']:
                    dll_dump_file_path_by_sha256[dll_record['sha256']] = dll_record['dump_file_path']

                elif dll_record['is_headerless']:
                    vollog.info('Module without PE header found {}'.format(dll_record['dump_file_path']))
                    headerless_dump_file_path_by_sha256[dll_record['sha256']] = dll_record['dump_file_path']

        for malfind_record in malfind_list:
            file_output = malfind_record['File output']

            if file_output == 'Error outputting to file':
                vollog.warning('Error dumping file {}, {}'.format(
                    malfind_record.get('PID'), malfind_record.get('Start VPN')))
                continue

            is_new_header = Intezer._populate_record_with_file_info(
                output_dir, file_output, sha256_by_header_hash, malfind_record, malfind=True)

            if is_new_header:
                if malfind_record['is_headerless']:
                    vollog.info('Non-PE executable section found with malfind {}, {}'.format(
                        malfind_record['dump_file_path'], malfind_record['sha256']))

                    headerless_dump_file_path_by_sha256[malfind_record['sha256']] = malfind_record['dump_file_path']

                elif not malfind_record['is_headerless']:
                    vollog.warning('Injected PE found with malfind {}, {}'.format(
                        malfind_record['dump_file_path'], malfind_record['sha256']))
                    injected_module_dump_file_path_by_sha256[malfind_record['sha256']] = malfind_record[
                        'dump_file_path']

        return (dll_dump_file_path_by_sha256,
                headerless_dump_file_path_by_sha256,
                injected_module_dump_file_path_by_sha256)

    @staticmethod
    def _build_loaded_modules_info_dict(dll_list: typing.List[dict], processes_info: dict, max_file_size: int) -> dict:
        loaded_modules_info = defaultdict(list)
        for dump_info in dll_list:
            if not dump_info.get('size'):
                continue

            if dump_info['size'] > max_file_size:
                continue

            pid = dump_info['PID']
            loaded_module_info = dict(image_type=processes_info[pid]['image_type'],
                                      base_address=(dump_info['Base'] or 0),
                                      mapped_size_in_bytes=(dump_info['size'] or 0),
                                      file_path=(dump_info['Path'] or 'N/A'))
            loaded_modules_info[pid].append(loaded_module_info)
        return loaded_modules_info

    @staticmethod
    def _build_injected_modules_info_dict(malfind_list: typing.List[dict], max_file_size: int) -> typing.List[dict]:
        injected_modules_info = [
            dict(base_address=(malfind_record['Start VPN'] or 0), pid=malfind_record['PID'])
            for malfind_record in malfind_list
            if malfind_record.get('size', sys.maxsize) <= max_file_size and not malfind_record['is_headerless']]

        return injected_modules_info

    @staticmethod
    def _build_all_dumps_info(dlls_and_malfind: typing.Iterable[dict], max_file_size: int) -> typing.List[dict]:
        memory_dumps_info = list()
        reported_large_files = set()  # Using a set to aviod reporting on the same large file multiple times
        for dll_or_malfind in dlls_and_malfind:
            if not dll_or_malfind.get('size'):
                continue

            if dll_or_malfind['size'] > max_file_size:
                if dll_or_malfind['sha256'] not in reported_large_files:
                    reported_large_files.add(dll_or_malfind['sha256'])
                    vollog.info('Skipping file above max size ({}MB): {}, {}MB, {}'.format(
                        max_file_size / 1024 / 1024,
                        dll_or_malfind.get('File output'),
                        dll_or_malfind['size'] / 1024 / 1024,
                        dll_or_malfind['sha256']))
                continue

            memory_dump_info = dict(base_address=dll_or_malfind.get('Base') or dll_or_malfind.get('Start VPN'),
                                    pid=dll_or_malfind['PID'],
                                    sha256=dll_or_malfind['sha256'],
                                    is_fileless=dll_or_malfind['is_headerless'])

            memory_dumps_info.append(memory_dump_info)

        return memory_dumps_info

    def run(self):
        # Extracting relevant parameters
        max_file_size = min(self.config['max-file-size'], 150) * 1024 * 1024
        intezer_url = self.config.get('intezer-instance-url')
        intezer_key = self._get_intezer_api_key()

        # Extracting the output dir as we need it to access the dump files and cached results
        output_dir = self._get_output_dir()

        image_info = self._get_image_info(output_dir)

        with IntezerProxy(intezer_url, intezer_key) as proxy:  # type: IntezerProxy

            proxy.init_access_token()
            proxy.start_scan({'image_type': image_info['image_type']})

            # Assuming failure until successfully done
            end_reason = END_REASONS['FAILED']

            dlls_count = 0
            malfind_non_pe_sections_count = 0
            malfind_injected_pes_count = 0

            try:
                # Extracting relevant info from env vars
                computer_name, username_by_pid = self._get_env_vars_info(output_dir)

                # Get and dump DLLs
                dll_list = self._run_volatility_command_and_get_info(dlllist.DllList, output_dir, enable_dump=True)

                # Organizing dlls by pid
                dlls_by_pid = {pid: list(dlls_) for pid, dlls_ in itertools.groupby(dll_list, lambda row: row['PID'])}

                # Getting process list, adding username, and full path using data we already have
                processes_info = self._get_processes(username_by_pid, dlls_by_pid)

                # Get and dump injections using malfind
                malfind_list = self._run_volatility_command_and_get_info(malfind.Malfind, output_dir, enable_dump=True)

                # Organizing dump data for upload
                dll_dump_path_by_sha256, headerless_dump_path_by_sha256, injected_module_dump_path_by_sha256 = \
                    self.organize_dump_files_by_sha256(dll_list, malfind_list, output_dir)

                # Organizing metadata
                loaded_modules_info = self._build_loaded_modules_info_dict(dll_list, processes_info, max_file_size)
                injected_modules_info = self._build_injected_modules_info_dict(malfind_list, max_file_size)
                all_dumps_info = self._build_all_dumps_info(itertools.chain(dll_list, malfind_list), max_file_size)

                if not all_dumps_info:
                    vollog.error('No files were extracted')
                    return

                # Sending metadata
                proxy.send_host_info(
                    image_info['image_type'], image_info['symbols'], computer_name)

                proxy.send_processes_info(list(processes_info.values()))

                for pid, loaded_modules_list in loaded_modules_info.items():
                    if loaded_modules_list:
                        proxy.send_loaded_modules_info(pid, loaded_modules_list)

                if injected_modules_info:
                    proxy.send_injected_modules_info(injected_modules_info)

                # Checking which files are missing in the cloud
                dumps_to_upload = set(proxy.send_memory_module_dumps_info(all_dumps_info))

                headerless_files = set(headerless_dump_path_by_sha256.keys())
                headerless_files_to_upload = dumps_to_upload.intersection(headerless_files)

                injected_modules = set(injected_module_dump_path_by_sha256.keys())
                injected_modules_to_upload = dumps_to_upload.intersection(injected_modules)

                modules_to_upload = dumps_to_upload - headerless_files_to_upload
                modules_to_upload = modules_to_upload - injected_modules

                if modules_to_upload or headerless_files_to_upload:
                    vollog.info('Uploading Files')

                def upload_file(sha256_):
                    proxy.upload_collected_binaries(dll_dump_path_by_sha256[sha256_], 'memory')

                def upload_injected_modules(sha256_):
                    proxy.upload_collected_binaries(injected_module_dump_path_by_sha256[sha256_], 'memory')

                def upload_fileless(sha256_):
                    proxy.upload_collected_binaries(headerless_dump_path_by_sha256[sha256_], 'fileless')

                # Uploading files concurrently
                with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
                    list(executor.map(upload_file, modules_to_upload))
                    list(executor.map(upload_injected_modules, injected_modules_to_upload))
                    list(executor.map(upload_fileless, headerless_files_to_upload))

                end_reason = END_REASONS['DONE']

                # Stats to share with user
                dlls_count = len(set(
                    dll['sha256'] for dll in dll_list if dll.get('size') and dll['size'] <= max_file_size))

                malfind_injected_pes_count = len(set(
                    malfind['sha256'] for malfind in malfind_list
                    if malfind.get('size') and malfind['size'] <= max_file_size and not malfind['is_headerless']))

                malfind_non_pe_sections_count = len(set(
                    malfind['sha256'] for malfind in malfind_list
                    if malfind.get('size') and malfind['size'] <= max_file_size and malfind['is_headerless']))

            except KeyboardInterrupt:
                end_reason = END_REASONS['INTERRUPTED']

            except requests.HTTPError as e:
                vollog.exception(e.response.content)
                end_reason = END_REASONS['FAILED']
            except:
                vollog.exception(
                    'Error during execution. To identify the issue, run in verbose mode using -vv and share the output '
                    'with support@intezer.com '
                    '`vol.py -f [memdump] -o [output-dir] -vv windows.intezer.Intezer --intezer-key [api-key]`')
                end_reason = END_REASONS['FAILED']

            finally:
                proxy.end_scan(end_reason)

        return renderers.TreeGrid(
            [('Filed', str), ('Value', str)], [
                (0, ('Loaded modules found', str(dlls_count))),
                (0, ('Malfind injected PEs found', str(malfind_injected_pes_count))),
                (0, ('Malfind non-PE executable sections found', str(malfind_non_pe_sections_count))),
                (0, ('Scan status', end_reason)),
                (0, ('Scan URL', f'{proxy.base_url}/endpoint-analyses/{proxy.endpoint_analysis_id}'))
            ])

    @property
    def version(self):
        return self._version
