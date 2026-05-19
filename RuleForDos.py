import yaml
import datetime
import html
import re
from elasticsearch import Elasticsearch, exceptions
from elasticsearch_dsl import Search, Q
from smtp import GmailSender
import sys


def _sanitize_for_email(value: str) -> str:
    """
    Sanitize a string for safe inclusion in email subject or body.
    Removes line breaks and any characters that could be interpreted as email headers.
    """
    if not isinstance(value, str):
        value = str(value)
    # Remove CR/LF characters
    value = value.replace("\r", " ").replace("\n", " ")
    # Escape HTML to prevent injection in HTML-aware email clients
    return html.escape(value, quote=False)


def _sanitize_for_index(value: str) -> str:
    """
    Sanitize a string before indexing it back into Elasticsearch.
    Strips control characters and ensures the value is a plain string.
    """
    if not isinstance(value, str):
        value = str(value)
    # Remove non-printable/control characters
    value = re.sub(r"[\\x00-\\x1F\\x7F]", " ", value)
    # Collapse multiple spaces
    return re.sub(r"\s+", " ", value).strip()


class DOS:
    def __init__(self, rules_file_path, elasticsearch_hosts):
        # Load YAML rule from file using safe_load
        with open(rules_file_path, 'r') as f:
            self.rule = yaml.safe_load(f)

        # Connect to Elasticsearch
        self.es = Elasticsearch(elasticsearch_hosts)

    def process_kern_logs(self, index_name):
        today = datetime.datetime.now().date()
        query = Q('exists', field='Data')
        s = Search(using=self.es, index=index_name).query(query)

        # Process log entries
        try:
            for hit in s.scan():
                # Extract relevant fields (e.g., IP address, timestamp)
                message = hit.Data
                port = hit.port
                host = hit.Hostname
                out_timestamp = hit.Timestamp

                # Parse the timestamp from the hit
                timestamp = datetime.datetime.fromisoformat(hit['@timestamp'][:-1]).strftime("%Y-%m-%d")
                current_date = datetime.datetime.now().strftime("%Y-%m-%d")

                if timestamp == current_date:
                    # Safely evaluate condition: ensure proper key access
                    condition = self.rule['conditions'][2]
                    contains_check = condition.get('contains')
                    contain_check = condition.get('contain')

                    if (message == contains_check) or contain_check:
                        # Sanitize values before using them in email and indexing
                        safe_message = _sanitize_for_email(message)
                        safe_port = _sanitize_for_email(port)
                        safe_host = _sanitize_for_email(host)
                        safe_out_timestamp = _sanitize_for_email(out_timestamp)

                        alert = (
                            f"Incident detected: {safe_message} on port {safe_port} "
                            f"in host: {safe_host} on {safe_out_timestamp}"
                        )

                        # Send email notification
                        sender = GmailSender('env.txt')
                        sender.send_email('Incident Detected', alert)

                        # Prepare incident record for Elasticsearch
                        now = datetime.datetime.now()
                        formatted_date = now.strftime("%Y-%m-%d %H:%M:%S")
                        send_log_index = 'myindex'
                        detected_incident = {
                            'Timestamp': formatted_date,
                            'Hostname': _sanitize_for_index(host),
                            'Message': _sanitize_for_index(alert),
                            'Port': _sanitize_for_index(port)
                        }

                        # Index the sanitized incident
                        self.es.index(index=send_log_index, document=detected_incident)
                        break

        except AttributeError:
            print("\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
            print('The field you entered does not exist ')
            print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
        except exceptions.ConnectionError:
            print()
        except KeyboardInterrupt:
            sys.exit()