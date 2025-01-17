# Govir
The aim here is to have a small CLI that uploads files to VirusTotal and monitors the status of the analysis.
Shows user status about files and their analysis results.

Please note that this is prototype code and generated entirely by Cursor AI based on various prompts, and it is far from being anything useful.

## Best prompt so far
```
Build a Go CLI app that uploads files to Virus Total for analysis.
Use the VirusTotal3 API to achieve this.

User will need to provide a Virus Total API key, either via env var, config.yaml or CLI parameter.

User will need to provide a file, a list of file, a directory, a list of directories, or a mix of these.
In all cases (file, list of files, directory or list of directories), the app needs to recursively list all files that are available inside this context. For example: all the files provided, and all the files in all the directories provided.

Example call when built:
VT_API_KEY=bleh ./govir this.file.exe this_directory "that file.exe"

1. Uploading the files
The file should be uploaded via Virus Total, using their VT Private Scanning services. Given the files can be larger than 32MB, an upload_url will need to be acquired for this.
All the files provided must be uploaded.

A comment must be added to the Virus Total job, using the designated API endpoint, with the user input for file. In case the input is not a single file, but a directory, and therefore a result of recursife file listing, the directory/file should be added in the comment.

2. Report
It takes some time for Virus Total to scan the files. The app must monitor this progress, and shown a subset of the report Virus Total is generating.
The file report API endpoint returns JSON. From a reporting perspective, we only care about the "last_analysis_results" leaf, and the data inside it. It includes a list of all virus scanners it uses to scan the files, for example:

            "last_analysis_results": {
                "Bkav": {
                    "method": "blacklist",
                    "engine_name": "Bkav",
                    "engine_version": "2.0.0.1",
                    "engine_update": "20250108",
                    "category": "undetected",
                    "result": null
                },

When a virus is not found by the virus scanner engine name, the "category" will set to be "undetected"
When category value is not "undetected", it is either a threat, a malicious alert or similar, with the type of virus outlined. Example:

                "Avira": {
                    "method": "blacklist",
                    "engine_name": "Avira",
                    "engine_version": "8.3.3.20",
                    "engine_update": "20250117",
                    "category": "malicious",
                    "result": "HEUR/AGEN.1376865"
                },

This means that "Avira" engine has found the uploaded file to be "malicious" by the HEUR/AGEN.1376865 called virus.

Further examples:
               "Cynet": {
                    "method": "blacklist",
                    "engine_name": "Cynet",
                    "engine_version": "4.0.3.4",
                    "engine_update": "20250117",
                    "category": "malicious",
                    "result": "Malicious (score: 99)"
                },

                "Fortinet": {
                    "method": "blacklist",
                    "engine_name": "Fortinet",
                    "engine_version": "None",
                    "engine_update": "20250117",
                    "category": "malicious",
                    "result": "PossibleThreat.PALLAS.H"
                },

Overall, please be friendly to Virus Total's API, don't hammer it.

About the CLI UI:
The user will need to see the status of each file to be uploaded. No progress bar, but a single status display of: pending, uploading, waiting for results, done.
Once the upload process is complete, and when virus total analyzes, the followings should be displayed:
- when Virus Total is in the process of scanning the file (report incomplete): processing
- when Virus Total reports no issue from all the engine, the user should see "clean" as a final status.
- when Virus total reports issues from one or more engines, the engine and the reported threat/malicious value should be displayed.

So something like this:
svc.exe: clean
test1/svc.exe: issues reported
- Avira (no cloud): HEUR/AGEN.1376865
- Cynet: Malicious (score: 99)
- WithSecure: Heuristic.HEUR/AGEN.1376865
test2/svc1.exe: issues reported
- Microsoft: Program:Win32/Wacapew.C!ml
test2/svc2.exe (results link): clean

The program should exit, when all the files requested received their complete report from Virustotal.
```

## References used:
- VirusTotal v3 API Documentation
- Dockerfile documentation
- Docker compose documentation