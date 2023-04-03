# from RuleForApacheBruteforce import HttpBruteforce
# from RuleForSshBruteforce import SshBruteforce
# from RuleForDos import DOS
# from elasticsearch import exceptions
# import sys
# import threading

# # Define a function to run the HttpBruteforce engine in a separate thread
# def run_http_engine():
#     HttpEngine = HttpBruteforce('rules.yaml', ['http://3.229.13.155:9200'])
#     HttpEngine.process_auth_logs('access_log')

# # Define a function to run the SshBruteforce engine in a separate thread
# def run_ssh_engine():
#     SshEngine = SshBruteforce('rules.yaml', ['http://3.229.13.155:9200'])
#     SshEngine.process_auth_logs('test')

# # Define a function to run the DOS engine in a separate thread
# def run_dos_engine():
#     DosEngine = HttpBruteforce('rules.yaml', ['http://3.229.13.155:9200'])
#     DosEngine.process_auth_logs('doslog')

# try:
#     # Create a list of threads for each engine
#     threads = [
#         threading.Thread(target=run_http_engine),
#         threading.Thread(target=run_ssh_engine),
#         threading.Thread(target=run_dos_engine)
#     ]

#     # Start all threads at the same time
#     for thread in threads:
#         thread.start()

#     # Wait for all threads to complete
#     for thread in threads:
#         thread.join()

# except exceptions.ConnectionError:
#     print("\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n")
#     print('Elascticsearch not connected. Elasticsearch seems down \n')
#     print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n")
#     sys.exit()
# except KeyboardInterrupt:
#     sys.exit()


