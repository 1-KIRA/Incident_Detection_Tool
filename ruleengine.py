import logging
from datetime import datetime, timedelta
import yaml

class RuleEngine:
    def __init__(self, rules_file):
        # Set up logger
        logging.basicConfig(filename='ruleengine.log', level=logging.DEBUG)

        # Load rules from YAML file
        with open(rules_file, 'r') as stream:
            try:
                self.rules = yaml.safe_load(stream)
            except yaml.YAMLError as exc:
                logging.error(f"Error loading rules from {rules_file}: {exc}")

    def match(self, log):
        for rule in self.rules:
            matched = True
            for condition in rule["conditions"]:
                field = condition["when"]["field"]
                value = condition["when"]["value"]
                within = timedelta(seconds=condition["within"])

                # Filter logs that match the condition
                logs = [l for l in log if (field) == value]

            if matched:
                actions = rule["actions"]
                # Log the matched rule
                logging.info(f"Matched rule: {rule}")
                return actions
        return []
