# GCPBucketBrute

A script to enumerate Google Storage buckets, determine what access you have to them, and determine if they can be privilege escalated.

- This script (optionally) accepts GCP user/service account credentials and a keyword.
- Then, a list of permutations will be generated from that keyword which will then be used to scan for the existence of Google Storage buckets with those names.
- If credentials are supplied, the majority of enumeration will still be performed while unauthenticated, but for any bucket that is discovered via unauthenticated enumeration, it will attempt to enumerate the bucket permissions using the TestIamPermissions API with the supplied credentials. This will help find buckets that are accessible while authenticated, but not while unauthenticated.
- Regardless if credentials are supplied or not, the script will then try to enumerate the bucket permissions using the TestIamPermissions API while unauthenticated. This means that if you don't enter credentials, you will only be shown the privileges an unauthenticated user has, but if you do enter credentials, you will see what access authenticated users have compared to unauthenticated users.
- **WARNING:** If credentials are supplied, your username can be disclosed in the access logs of any buckets you discover.

## TL;DR Summary
- Given a keyword, this script enumerates Google Storage buckets based on a number of permutations generated from the keyword.
- Then, any discovered bucket will be output.
- Then, any permissions that you are granted (if any) to any discovered bucket will be output.
- Then the script will check those privileges for privilege escalation (storage.buckets.setIamPolicy) and will output anything interesting (such as publicly listable, publicly writable, authenticated listable, privilege escalation, etc).

## Requirements

- Linux/OS X
	- Windows only works for unauthenticated scans. Something is wrong with how the script uses the subprocess module in that it fails when using an authenticated Google client.
- Python3
- Pip3

## Installation

1. `git clone https://github.com/RhinoSecurityLabs/GCPBucketBrute.git`
2. `cd GCPBucketBrute/`
3. `pip3 install -r requirements.txt` or `python3 -m pip install -r requirements.txt`

## Usage

First, determine the type of authentication you want to use for enumeration between a user account, service account, or unauthenticated. If you are using a service account, provide the file path to the private key via the `-f`/`--service-account-credential-file-path` argument. If you are using a user account, don't provide an authentication argument. You will then be prompted to enter the access token of your user account for accessing the GCP APIs. If you want to scan completely unauthenticated, pass the `-u`/`--unauthenticated` argument to hide authentication prompts.

- Scan for buckets using the keyword "test" while completely unauthenticated:
```
python3 gcpbucketbrute.py -k test -u
```

- Scan for buckets using the keyword "test" while authenticating with a service account (private key stored at ../sa-priv-key.pem), outputting results to out.txt in the current directory:
```
python3 gcpbucketbrute.py -k test -f ../sa-priv-key.pem -o ./out.txt
```

- Scan for buckets using the keyword "test", using a user account access token, running with 10 subprocesses instead of 5:
```
python3 gcpbucketbrute.py -k test -s 10
```

### Available Arguments

- `-k`/`--keyword`
    - This argument is used to specify what keyword will be used to generate permutations with. Those permutations are what will be searched for in Google Storage.
- `--check`
    - This argument is mutually exclusive with `-k`/`--keyword` and accepts a single string. It allows you to check your permissions on a particular bucket, rather than generating a list of permutations based on a keyword. This may be repeated to check several buckets. Credit: [@BBerastegui](https://github.com/BBerastegui)
- `--check-list`
    - This argument is mutually exclusive with `-k`/`--keyword` and `--check`. It allows you to check permissions of a list of buckets in a file. They should be listed one-per-line in a text file. To read from standard input, pass `-` as the filename.
- `-s`/`--subprocesses`
    - This argument specifies how many subprocesses will be used for bucket enumeration. The default is 5 and the higher you set this value, the faster enumeration will be, but your requests-per-second to Google will increase. These are essentially threads, but the script uses subprocesses instead of threads for parallel execution.
- `-f`/`--service-account-credential-file-path`
    - This argument is where you specify the path to the private key file of the GCP service account you want to use to authenticate to Google Storage with. This is optional. If you want to use an access token instead, omit this argument and you will be prompted for the token so it is not saved to your command line history. More information here: https://google-auth.readthedocs.io/en/latest/user-guide.html#service-account-private-key-files and here: https://google-auth.readthedocs.io/en/latest/user-guide.html#user-credentials
- `-u`/`--unauthenticated`
    - This argument forces unauthenticated enumeration. With this flag, you will not be prompted for credentials and valid buckets will not be checked for authenticated permissions.
- `-o`/`--out-file`
    - This argument allows you to specify a (relative or absolute) file path to a log file to output the results to. The file will be created if it does not already exist and it will be appended to if it does already exist.
- `-w`/`--wordlist`
    - This argument allows you to specify a wordlist input file.
