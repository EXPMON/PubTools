import os
import sys
import time
import zlib
import json
import codecs
import shutil
import requests
import argparse
import datetime



#server address
server_url = 'https://pub.expmon.com'

url_submission = server_url + '/submit/api/expmon_submit_file'
url_query_prefix = server_url + '/analysis/api/query/'







class Logger(object):
    def __init__(self):
        self.terminal = sys.stdout
        self.log = open("analysis_%s.log" % int(datetime.datetime.utcnow().timestamp()), "a")
  
    def write(self, message):
        self.terminal.write(message)
        self.log.write(message)

    def flush(self):
        pass    





def expmon_submit_file(sample_path, dump_raw_logs = False):

    print("[INFO] Submitting sample <%s>" % sample_path.encode("utf-8"))

    sample_name = os.path.basename(sample_path)

    #sample submission
    files = {'file_data': (sample_name, open(sample_path, 'rb'))}
    response = requests.post(url_submission, files = files, verify = True, timeout = 300)
    resp = response.json()
    print(str(resp))

    sample_sha256 = resp['sha256']
    sample_uuid = resp['uuid']
    print('[INFO] Submitted sample hash: ' + sample_sha256)
    print('[INFO] Submitted sample uuid: ' + sample_uuid)
    
    time.sleep(15)


    #continue to check until the server returns analysis result
    while 1:
        
        response = requests.get(url_query_prefix + sample_sha256 + '/' + sample_uuid + '/', verify = True)
        resp = response.json()

        #code 0 means we get the result
        if resp['code'] == 0:
            break
        #code 1 means sample is being analyzed
        elif resp['code'] == 1:
            print('[INFO] Sample is being analyzed, wait additional 15 seconds')
        elif resp['code'] == 2:
            print('[INFO] Sample is pending to be analyzed, wait additional 15 seconds')
        else:
            print('UNKNOWN ERROR: %s' % resp['message'])
            exit(-1)

        time.sleep(15)
        

    if dump_raw_logs:
        #all sandbox logs dumpped to analysis_logs folder
        folder_root = os.path.join("analysis_logs", sample_sha256)

        if os.path.exists(folder_root):
            print('[INFO] directory already exists, removing it.')
            shutil.rmtree(folder_root)
        os.makedirs(folder_root)


    #print overall detection result
    detection_obj = json.loads(resp['detection'])
    print('Detection Result: ' + detection_obj['result'])
    print('Detection Description: ' + str(detection_obj['desc']))


    #print detailed analysis result based on file objects
    file_objects = resp['file_objects']


    i = 0
    for file_obj in file_objects:

        i = i + 1

        print("file object %d:" % i)
        print("\t md5: %s" % file_obj['md5'])
        print("\t sha1: %s" % file_obj['sha1'])
        print("\t sha256: %s" % file_obj['sha256'])
        print("\t file type: %s" % file_obj['file_type'])
        print("\t page number: %d" % file_obj['page_num'])
        print("\t object analysis start time: %s" % str(file_obj['analysis_start_time']))
        print("\t object analysis finish time: %s" % str(file_obj['analysis_finish_time']))

        
        object_detection_result = json.loads(file_obj['detection'])
        print("\t object analysis result: %s" % object_detection_result['result'])
        print("\t object analysis description: %s" % object_detection_result['desc'])


        file_analysis_logs = json.loads(file_obj['analysis_logs'])
        
        if dump_raw_logs:
            #make folder to dump analysis logs
            obj_folder_name = '%s__%s' % (file_obj['sha256'], file_obj['file_type'])
            folder_pathname = os.path.join(folder_root, obj_folder_name)
            os.makedirs(folder_pathname)


        env_count = 0       
        for env_name in file_analysis_logs:

            env_count = env_count + 1
            print("\t test env %d: %s" % (env_count, env_name))

            if dump_raw_logs:
                folder_pathname_env = os.path.join(folder_pathname, env_name)
                os.makedirs(folder_pathname_env)

            
            for log_type in file_analysis_logs[env_name]:

                
                if log_type == "indicators":
                    indicators = file_analysis_logs[env_name][log_type]
                    print("\t " + str(indicators))
                else:

                    if dump_raw_logs:
                        log_data_hexstr = file_analysis_logs[env_name][log_type]
                        if log_data_hexstr == '' or log_data_hexstr == None:
                            continue

                        #log data is hex string in the traffic and is compressed
                        log_data = zlib.decompress(codecs.decode(log_data_hexstr, 'hex'))
                        
                        #dump log data to file
                        log_file_name = os.path.join(folder_pathname_env, log_type + '.txt')
                        #print(log_file_name)
                        open(log_file_name, "wb").write(log_data)





def is_known_unsupported(sample_path):

    #protect from potential io error
    try_count = 0
    while (1):
        try:
            file_size = os.path.getsize(sample_path)
            if file_size < 0x10:
                return True
            f = open(sample_path, "rb")
            s = f.read(0x10)
            f.close()
            break
        except:
            try_count = try_count + 1
            if try_count > 5:
                print("ERROR IN is_known_unsupported()!")
                exit(-1)
            time.sleep(1)
            
    #windows PE, not need to submit
    if s[0:2] == b"\x4D\x5A":
        return True

    #linux elf, no need to submit
    if s[0:4] == b"\x7F\x45\x4C\x46":
        return True

    return False
    







parser = argparse.ArgumentParser()

parser.add_argument('target_path', help = 'sample path or folder path that contains multiple samples')
parser.add_argument('-exclude-known', '--exclude_known_formats', action='store_true', help='if set, files with known unsupported file header signature will not be uploaded')
parser.add_argument('-exclude-ext', '--exclude_ext_names', required=False, help='exclude files with extention names, must start with a ".", use ";" for multiple extention names, example: -exclude-ext=".png;.jpg"')
parser.add_argument('-dump-raw', '--dump_raw_logs', action='store_true', help='if set, sandbox logs will be dumped into the "analysis_logs" folder')


args = parser.parse_args()



target_path = args.target_path

exclude_extname_list = None
if args.exclude_ext_names:
    exclude_extname_list = args.exclude_ext_names.lower().split(";")



sample_list = []



    
if os.path.isfile(args.target_path):

    print("""\n************************************************************ WARNING ************************************************************
The file <%s> will be uploaded to %s for analysis.
You need to be absolutely sure what you're doing. DO NOT UPLOAD CONFIDENTIAL FILES OR FILES YOU'RE NOT ALLOWED TO SHARE!
More, you may read our Terms of Service and Privacy Policy at our website %s
*********************************************************************************************************************************""" % (args.target_path, server_url, server_url))

    sample_list = [args.target_path]


elif os.path.isdir(args.target_path):

    print("""\n************************************************************ WARNING ************************************************************
All the files in the folder <%s> including sub-folders will be uploaded to %s for analysis.
You need to be absolutely sure what you're doing. DO NOT UPLOAD CONFIDENTIAL FILES OR FILES YOU'RE NOT ALLOWED TO SHARE!
More, you may read our Terms of Service and Privacy Policy at our website %s
*********************************************************************************************************************************""" % (args.target_path, server_url, server_url))

    for root, dirs, files in os.walk(args.target_path):
        for name in files:
            sample_path = os.path.join(root, name)

            if args.exclude_known_formats:
                if is_known_unsupported(sample_path):
                    continue

            if exclude_extname_list:
                ext_name = "." + sample_path.split(".")[-1]
                if ext_name.lower() in exclude_extname_list:
                    continue

            sample_list.append(sample_path)



else:
    print("Error - the target path is not valid.")
    exit(-1)




print("""\nAnalysis logs will be logged into two parts:
1) A text file named 'analysis_<int>.log' in the current directory. It contains all the detection information returned by the EXPMON system.
2) If the flag '-dump-raw' is set, raw sandbox logs will be saved in the "analysis_log" directory. Your OS may need to support long path name \
because there will be long folder names in that directory. Raw sandbox logs are for advanced users.
""")



print("\nThe following files will be uploaded to EXPMON for analysis:\n")
for sample_path in sample_list:
    print(sample_path)
print("\nTotal number of files will be uploaded to EXPMON for analysis: %d\n" % len(sample_list))

answer = input("Please confirm to continue ('y' to continue, other to stop):")
if answer != 'y':
    exit(-1)

    

#start submitting
print("\n")


#log to file
sys.stdout = Logger()


#submit the samples one by one
for sample_path in sample_list:

    #protect from potential network or io error
    try_count = 0
    while (1):
        try:
            expmon_submit_file(sample_path, args.dump_raw_logs)
            break
        except:
            try_count = try_count + 1
            if try_count > 5:
                print("ERROR IN expmon_submit_file()")
                exit(-1)
            time.sleep(15)
            
    print("\n")

