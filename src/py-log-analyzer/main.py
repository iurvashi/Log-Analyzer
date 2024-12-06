#! bin/env/python3

import re, csv


class Record:
    def __init__(self, log: str):
        self.ip = re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", log)[0]
        self.timestamp = re.search(r"\[(.*?)]", log)[0]
        self.method = re.search(r"[A-Z]{3,4}", log)[0]
        self.endpoint = re.search(r"/\w+ ", log)[0].strip()
        self.protocol = re.search(r"HTTP/\d\.\d", log)[0]
        self.status_code = re.search(r"\" (\d{3})", log)[0].split(" ")[1]
        self.response_size = re.search(r"\" (\d{3}) (\d+)(?: |$)", log)[0].split(" ")[2]
        self.message = re.search(r"\"([^\"]+)\"$", log)
        if self.message:
            self.message = self.message[0]


class RecordStore:
    def __init__(self):
        self.records = []

    def __iter__(self):
        return iter(self.records)

    def __iadd__(self, record: Record):
        self.records.append(record)
        return self


if __name__ == "__main__":
    log_file = open("sample.log", "r")

    record_store = RecordStore()
    for log in log_file:
        record_store += Record(log.strip())

    ip_request_count = {}
    for record in record_store:
        if record.ip in ip_request_count:
            ip_request_count[record.ip] += 1
        else:
            ip_request_count[record.ip] = 1
    ip_request_count = dict(sorted(ip_request_count.items(), key=lambda item: item[1], reverse=True))

    endpoint_access_count = {}
    for record in record_store:
        if record.endpoint in endpoint_access_count:
            endpoint_access_count[record.endpoint] += 1
        else:
            endpoint_access_count[record.endpoint] = 1
    endpoint_access_count = dict(sorted(endpoint_access_count.items(), key=lambda item: item[1], reverse=True))

    invalid_requests = {}
    for record in record_store:
        if record.status_code == "401":
            if record.ip in invalid_requests:
                invalid_requests[record.ip] += 1
            else:
                invalid_requests[record.ip] = 1
    invalid_requests = dict(sorted(invalid_requests.items(), key=lambda item: item[1], reverse=True))

    print(f"{'IP Address':<20}{'Request Count':<20}")
    for ip, request_count in ip_request_count.items():
        print(f"{ip:<20}{request_count:<20}")

    print("-"*50)

    print(f"Most Frequently Accessed Endpoints:")
    for endpoint, access_count in endpoint_access_count.items():
        print(f"{endpoint:<20}{access_count:<20}")

    print("-"*50)

    print(f"Suspicious Activity Detected:")
    print(f"{'IP Address':<20}{'Failed Login Attempts':<20}")
    for ip, request_count in invalid_requests.items():
        print(f"{ip:<20}{request_count:<20}")

    with open("log_analysis_results.csv", "w") as f:
        writer = csv.writer(f)

        writer.writerow(["IP Address", "Request Count"])
        for ip, request_count in ip_request_count.items():
            writer.writerow([ip, request_count])

        writer.writerow([])

        writer.writerow(["Most Frequently Accessed Endpoints"])
        for endpoint, access_count in endpoint_access_count.items():
            writer.writerow([endpoint, access_count])

        writer.writerow([])

        writer.writerow(["Suspicious Activity Detected"])
        writer.writerow(["IP Address", "Failed Login Attempts"])
        for ip, request_count in invalid_requests.items():
            writer.writerow([ip, request_count])
            