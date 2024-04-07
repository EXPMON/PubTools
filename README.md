# EXPMON Submission Helper Tool - expmon_sample_submit.py

## Introduction

The "expmon_sample_submit.py" is a helper tool for automatically submitting samples to EXPMON Public and obtaining analysis results, via EXPMON Web APIs. It can submit a single file or mutiple files from a folder.

By using this tool you agree to our [Terms of Services](https://pub.expmon.com/static/pdf/tos.pdf) and [Privacy Policy](https://pub.expmon.com/static/pdf/privacy.pdf). Please note that we provide the service on an "AS IS" basis and offer no warranty of any kind.

**DO NOT UPLOAD CONFIDENTIAL FILES OR FILES YOU'RE NOT ALLOWED TO SHARE!**

We highly recommend reading the [Methodology & Architecture](https://pub.expmon.com/static/pdf/expmon_methodology_architecture.pdf) and the [Web UI & APIs](https://pub.expmon.com/static/pdf/expmon_ui_apis.pdf) documents first if you haven't already done so, to better understand the system and how to use it properly.

If you have any questions when using this tool, please feel free to email us at contact@expmon.com.




## Usage

Using the tool is pretty straightforward, as shown by the command "python expmon_sample_submit.py -h":

```
usage: expmon_sample_submit.py [-h] [-exclude-known] [-exclude-ext EXCLUDE_EXT_NAMES] [-dump-raw] target_path

positional arguments:
  target_path           sample path or folder path that contains multiple samples

options:
  -h, --help            show this help message and exit
  -exclude-known, --exclude_known_formats
                        if set, files with known unsupported file header signature will not be uploaded
  -exclude-ext EXCLUDE_EXT_NAMES, --exclude_ext_names EXCLUDE_EXT_NAMES
                        exclude files with extention names, must start with a ".", use ";" for multiple extention names, example: -exclude-ext=".png;.jpg"
  -dump-raw, --dump_raw_logs
                        if set, sandbox logs will be dumped into the "analysis_logs" folder
```

Users will have a chance to review what they are going to submit before really submitting. For example:

```
The following files will be uploaded to EXPMON for analysis:

C:\expmon\samples\sample-simple-1.xlsx

Total number of files will be uploaded to EXPMON for analysis: 1

Please confirm to continue ('y' to continue, other to stop):
```




## Examples

* The following will submit the file "C:\expmon\samples\sample-simple-1.xlsx", and wait for the result. Analysis results will be displayed as well as logged into a file named like "analysis_{int}.log" in current working directory.

  ```
  python expmon_sample_submit.py "C:\expmon\samples\sample-simple-1.xlsx"
  ```


* The following will submit all the files in the "C:\expmon\samples" folder, and wait for the results. Analysis results will be displayed as well as logged into a file named like "analysis_{int}.log" in current working directory.

  ```
  python expmon_sample_submit.py "C:\expmon\samples"
  ```


* The following will submit all the files in the "C:\expmon\samples" folder, and wait for the results. Analysis results will be displayed as well as logged into a file named like "analysis_{int}.log" in current working directory. Additionally, the raw sandbox logs will be dumped into a folder named "analysis_log" in the current working directory.

  ```
  python expmon_sample_submit.py "C:\expmon\samples" -dump-raw
  ```
  On Windows, you may need to enable long path support if you use "-dump-raw" because under the "analysis_log" folder there will be long-name folders named after sandbox environment names.


* The following will submit all the files in the "C:\expmon\samples" folder except those files whose header signature is abslotely known of being unsupported by EXPMON (so you don't need to submit them and that saves EXPMON's resource), and wait for the results. Analysis results will be displayed as well as logged into a file named like "analysis_{int}.log" in current working directory.

  ```
  python expmon_sample_submit.py "C:\expmon\samples" -exclude-known
  ```


* The following will submit all the files in the "C:\expmon\samples" folder except those files with certain extension names, and wait for the results. Analysis results will be displayed as well as logged into a file named like "analysis_{int}.log" in the current working directory.

  Please note that determining the file type by the extension name may not be stable, that means it may miss some exploits because those samples will not be submitted. However, it may help in some cases when you know absolutely that the file types of the sample set are properly classified.

  
  ```
  python expmon_sample_submit.py "C:\expmon\samples" -exclude-ext=".png;.jpg"
  ```
