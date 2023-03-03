from elasticsearch_query import ElasticsearchQuery
import yaml

class RuleEngine(ElasticsearchQuery):
    def __init__(self, host, port, rules_file):
        super().__init__(host, port)
        with open(rules_file, 'r') as file:
            self.rules = yaml.load(file, Loader=yaml.FullLoader)

    def apply_rules(self, log_data):
        for rule in self.rules:
            if self._evaluate_conditions(rule['conditions'], log_data):
                for action in rule['actions']:
                    self._execute_action(action, log_data)

    def _evaluate_conditions(self, conditions, log_data):
        for condition in conditions:
            field = condition['when']['field']
            value = condition['when']['value']
            if field in log_data and log_data[field] == value:
                return True
        return False

    def _execute_action(self, action, log_data):
        if action['action'] == 'log':
            print(action['message'] % log_data)
        elif action['action'] == 'set':
            log_data[action['field']] = action['value']
        else:
            raise Exception(f"Unknown action {action['action']}")
