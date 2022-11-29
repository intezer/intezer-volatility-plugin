# Intezer Volatility 3 Plugin (beta)
Intezer plugin for Volatility 3 - memory dump analysis using Intezer.

## About the plugin
- Detects and analyzes malware, memory injections, and other threats in memory images.
- Supports all Windows versions
- Requires [Volatility 3](https://github.com/volatilityfoundation/volatility3) (for Intezer Volatility 2 plugin, please get in touch with support@intezer.com)
- If you're looking to scan live machines, see [Intezer's endpoint scanner](https://support.intezer.com/hc/en-us/articles/360021350340-Conducting-Live-Endpoint-Analysis)

## How it works
- Dumps loaded modules and potential injections
- Analyzes them using [Intezer](https://www.intezer.com/)'s code analysis
- Provides verdict, classification, and clear view of all code found in the memory image

## Getting started
- Install [Volatility 3](https://github.com/volatilityfoundation/volatility3)
- Install the plugin's dependencies:
	```shell
	pip install requests tenacity
	```
- Download the [plugin file `intezer.py`](https://raw.githubusercontent.com/intezer/intezer-volatility-plugin/main/intezer.py) from this repository and store it in Volatility's Windows plugins directory `volatility3/volatility3/framework/plugins/windows/intezer.py`
- Get your Intezer API key from https://analyze.intezer.com/account-details
- Create an empty output directory. *Defining an output directory is critical. The plugin stores dump files and cache files. You can remove it after execution.*
- From the `volatility3` directory, execute the plugin:
	```shell
	python vol.py -f [memdump] -o [output-dir] windows.intezer --intezer-key [api-key]
	```
- The plugin outputs the scan URL to view it in the Intezer web console. You also can find your scan history at https://analyze.intezer.com/history?tab=endpoint.

## Troubleshooting
If you encounter an issue, you can execute the plugin with the verbose flag `-vv` to display all the logs
```shell
python vol.py -f [memdump] -o [output-dir] -vv windows.intezer --intezer-key [api-key]
```
Or write all logs into a file using the `-l` option
```shell
python vol.py -f [memdump] -o [output-dir] -l intezer-volatility-plugin-log.txt windows.intezer --intezer-key [api-key]
```
Then contact us at support@intezer.com and attach the complete log.
