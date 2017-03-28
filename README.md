# Python AWS CloudTrail parser
A Python parser class for [CloudTrail](https://aws.amazon.com/cloudtrail/) event archives, previously dumped to an S3 bucket. Class provides an iterator which will:

- Scan a given directory for archive files and JSON file matching the required pattern.
- If archive files, decompress each archive in memory.
- Parse JSON payload and return each event in turn.

Parser contained in `cloudtrailparser.py`, with `timezone` class used as a simple [`datetime.tzinfo`](https://docs.python.org/2/library/datetime.html#datetime.tzinfo) concrete class implement to provide UTC timezone.

## Example

```sh
$ ls -l1 /path/to/cloudtrail/archives
ACCOUNT_IDXX_CloudTrail_ap-southeast-2_20160101T2155Z_uiGgE0mgD8GUpvNi.json.gz
ACCOUNT_IDXX_CloudTrail_ap-southeast-2_20160101T2305Z_BNBEUH14QUAV0dNd.json.gz
ACCOUNT_IDXX_CloudTrail_ap-southeast-2_20170303T0000Z_4qtJmjZy88xW59bU.json

$ ./example.py

Event name: ListContainerInstances
Event time: 2016-01-01 23:02:08+00:00

Event name: DescribeContainerInstances
Event time: 2016-01-01 23:02:08+00:00

Event name: ListContainerInstances
Event time: 2016-01-01 23:02:11+00:00

Event name: DiscoverPollEndpoint
Event time: 2016-01-01 22:59:36+00:00

Event name: DescribeInstanceHealth
Event time: 2016-01-01 23:00:41+00:00
```
