import argparse
from cmd import Cmd
import copy
import json
import os
import requests
from typing import Callable


class ArgParser:
    def __init__(self):
        parser = argparse.ArgumentParser(description='ThousandEyes Reports Helper')
        parser.add_argument('-u', '--username', metavar='username', type=str, help='your username',
                            default=os.environ.get('THOUSANDEYES_USERNAME'))
        parser.add_argument('-t', '--token', metavar='API token', type=str, help='your API token',
                            default=os.environ.get('THOUSANDEYES_API_TOKEN'))

        args = parser.parse_args()
        self.username = args.username
        self.token = args.token

        if not self.username or not self.username.strip():
            print(F'Erroneous username: {self.username}')
            exit(2)

        if not self.token or not self.token.strip():
            print(F'Erroneous token: {self.token}')
            exit(2)


class ReportParser:
    def __init__(self):
        self.PERSISTENT_FILTERS = {'Connection', 'Platform'}
        self.filter_code_to_name_map = {
            'ea': 'Endpoint Agents',
            'eal': 'Endpoint Agent Labels',
            'loc': 'Location',
            'pn': 'Private Network',
            'net': 'Network',
            'mn': 'Monitored Network'
        }

    def get_template_report(self, raw_report: dict) -> dict:
        report = copy.deepcopy(raw_report)
        for w in report['widgets']:
            if 'numberCards' in w:
                for c in w['numberCards']:
                    c['filters'] = {k: v if k in self.PERSISTENT_FILTERS else [] for k, v in
                                    c['filters'].items()}
            elif 'filters' in w:
                w['filters'] = {k: v if k in self.PERSISTENT_FILTERS else [] for k, v in
                                w['filters'].items()}
        return report

    def change_filter_value(self, raw_report: dict, filter_code: str, new_filter_values: list) -> dict:
        if filter_code not in self.filter_code_to_name_map:
            print(F'The filter code {filter_code} is not supported\n')
            return raw_report

        filter_name = self.filter_code_to_name_map[filter_code]

        report = copy.deepcopy(raw_report)
        for w in report['widgets']:
            if 'numberCards' in w:
                for c in w['numberCards']:
                    c['filters'] = {k: new_filter_values if k == filter_name else v for k, v in
                                    c['filters'].items()}
            elif 'filters' in w:
                w['filters'] = {k: new_filter_values if k == filter_name else v for k, v in
                                w['filters'].items()}
        return report

    def add_filter_value(self, raw_report: dict, filter_code: str, new_filter_values: list) -> dict:
        if filter_code not in self.filter_code_to_name_map:
            print(F'The filter code {filter_code} is not supported\n')
            return raw_report

        filter_name = self.filter_code_to_name_map[filter_code]

        report = copy.deepcopy(raw_report)
        for w in report['widgets']:
            if 'numberCards' in w:
                for c in w['numberCards']:
                    c['filters'][filter_name] = new_filter_values
            elif 'filters' in w:
                w['filters'][filter_name] = new_filter_values
        return report

    def remove_filter(self, raw_report: dict, filter_code: str) -> dict:
        if filter_code not in self.filter_code_to_name_map:
            print(F'The filter code {filter_code} is not supported\n')
            return raw_report

        filter_name = self.filter_code_to_name_map[filter_code]

        report = copy.deepcopy(raw_report)
        for w in report['widgets']:
            if 'numberCards' in w:
                for c in w['numberCards']:
                    if filter_name in c['filters']:
                        del c['filters'][filter_name]
            elif 'filters' in w:
                if filter_name in w['filters']:
                    del w['filters'][filter_name]

        return report


class ReportCli(Cmd):
    intro = 'You are authorised! Type ? for help :P\nIMPORTANT: Check the documentation of each command before use!!\n'
    prompt = '> '
    INVALID_ARGUMENTS_MSG = 'Very invalid arguments over there\n'

    API_BASE = 'https://api.thousandeyes.com/v7'
    REPORT_API_BASE = 'https://api.thousandeyes.com/v7/reports'

    def __init__(self):
        super().__init__()

        self.arg_parser = ArgParser()

        self.session = requests.Session()
        self.session.auth = (self.arg_parser.username, self.arg_parser.token)
        self.session.params = {'format': 'json'}

        print('Welcome to Report Cli ;) Let me check your credentials first\n')
        self.check()

    def check(self):
        r = self.session.get(F'{self.REPORT_API_BASE}')
        if not r.ok:
            print('You are not authorised with the credential you gave me >( Identify yourself!')
            exit(2)

    def do_exit(self, arg):
        """
        Exit the CLI
        Usage: exit
        """
        print('Bye ;)')
        return True

    def do_get_report(self, arg):
        """
        Get raw report with ID and save it to a file
        Usage: get ID DESTINATION_FILE [ACCOUNT_GROUP_ID]

        ACCOUNT_GROUP_ID is optional. If not specified, try to fetch report from default account group
        """
        args = parse_arg(arg)
        if len(args) is 2:
            self.session.params = {}
        elif len(args) is 3:
            self.session.params = {'aid': args[2]}
        else:
            print(self.INVALID_ARGUMENTS_MSG)
            return False

        print('Getting your report')
        report = self.get_report(args[0])
        if report is None:
            return False

        with open(args[1], 'w') as f:
            f.write(json.dumps(report, indent=4))
            print('Your report is saved!\n')

        self.session.params = {}
        return False

    def do_get_template(self, arg):
        """
        Get report with filters cleared and save the template to a file
        Usage: get_template ID DESTINATION_FILE [ACCOUNT_GROUP_ID]

        ACCOUNT_GROUP_ID is optional. If not specified, try to fetch report from default account group
        """
        args = parse_arg(arg)
        if len(args) is 2:
            self.session.params = {}
        elif len(args) is 3:
            self.session.params = {'aid': args[2]}
        else:
            print(self.INVALID_ARGUMENTS_MSG)
            return False

        print('Getting your template report')
        report = self.get_report(args[0])
        if report is None:
            return False

        with open(args[1], 'w') as f:
            f.write(json.dumps(ReportParser().get_template_report(report), indent=4))
            print('Your template report is saved!\n')

        self.session.params = {}
        return False

    def do_get_endpoint_data(self, arg):
        """
        Get all the Endpoint Agents in a json format and store the list into a file.
        This is useful if you want to update the filter values. Call this to get the required new filter values
        (e.g. Endpoint Agent ID, Endpoint Agent label group id)
        Usage: get_endpoint_data DATA_TYPE DESTINATION_FILE

        DATA_TYPE list:
        EA  -- Endpoint Agents
        EAL -- Endpoint Agent Labels
        PN  -- Private Network

        Sadly location is not yet supported :(
        """
        args = parse_arg(arg)
        if len(args) is not 2:
            print(self.INVALID_ARGUMENTS_MSG)
            return False

        data_type_to_api_url_map = {
            'ea': F'{self.API_BASE}/endpoint-agents.json',
            'eal': F'{self.API_BASE}/groups/endpoint-agents.json',
            'pn': F'{self.API_BASE}/endpoint-data/networks.json'
        }

        data_type_code, destination_file_name = args
        data_type_code = data_type_code.lower()
        if data_type_code not in data_type_to_api_url_map:
            print(F'Unsupported data type code {data_type_code}')

        api_url = data_type_to_api_url_map[data_type_code]
        r = self.session.get(api_url)
        if not r.ok or r is None or r.text is None:
            print(F'Error :(\n')
            return False

        json.loads(r.txt)

        with open(destination_file_name, 'w') as f:
            f.write(json.dumps(json.loads(r.text), indent=4))
            print('All saved in the file!\n')
        return False

    def do_find_endpoint_agent(self, arg):
        """
        Find endpoint agent by keyword and store the result in destination file
        Usage: find_endpoint_agent DESTINATION_FILE SEARCH_KEYWORD [SEARCH_KEYWORD ...]
        """
        args = parse_arg(arg)
        if len(args) < 2:
            print(self.INVALID_ARGUMENTS_MSG)
            return False

        r = self.session.get(F'{self.API_BASE}/endpoint-agents.json')
        if not r.ok or r is None or r.text is None:
            print(F'Error :(\n')
            return False

        with open(args[0], 'w') as f:
            f.write(json.dumps(json.loads(r.text), indent=4))
            print('All saved in the file!\n')
        return False

    def do_add_filter(self, arg):
        """
        Add a new filter to all the widgets
        Usage: add_filter ID FILTER_NAME FILTER_VALUES_FILE [ACCOUNT_GROUP_ID]

        ACCOUNT_GROUP_ID is optional. If not specified, try to add filter to the report from default account group

        FILTER_NAME list:
        EA  -- Endpoint Agents
        EAL -- Endpoint Agent Labels
        LOC -- Location
        PN  -- Private Network
        NET -- Network
        MN  -- Monitored Network

        Note: when changing filter of Endpoint Agents use agent ID!!
        """
        args = parse_arg(arg)
        if len(args) is 3:
            self.session.params = {}
        elif len(args) is 4:
            self.session.params = {'aid': args[3]}
        else:
            print(self.INVALID_ARGUMENTS_MSG)
            return False

        return self.update_report_filter(args[:3], ReportParser().add_filter_value)

    def do_remove_filter(self, arg):
        """
        Remove the filter in all widget
        Usage: remove_filter REPORT_ID FILTER_NAME [ACCOUNT_GROUP_ID]

        ACCOUNT_GROUP_ID is optional. If not specified, try to remove the filter in report from default account group


        FILTER_NAME list:
        EA  -- Endpoint Agents
        EAL -- Endpoint Agent Labels
        LOC -- Location
        PN  -- Private Network
        NET -- Network
        MN  -- Monitored Network
        """
        args = parse_arg(arg)
        if len(args) is 2:
            self.session.params = {}
        elif len(args) is 3:
            self.session.params = {'aid': args[2]}
        else:
            print(self.INVALID_ARGUMENTS_MSG)
            return False

        report_id, filter_code = args[:2]

        raw_report = self.get_report(report_id)
        if raw_report is None:
            return False

        new_report = ReportParser().remove_filter(raw_report, filter_code.lower())
        if new_report != raw_report:
            self.session.post(F'{self.REPORT_API_BASE}/{report_id}/update', json=new_report)
            print('Done!\n')

        self.session.params = {}
        return False

    def do_change_filter_value(self, arg):
        """
        Change the filter's value in the report, the new filter values is specified in a file where the values are
        separated with a newline.
        Usage: change_filter_value ID FILTER_NAME FILTER_VALUES_FILE [ACCOUNT_GROUP_ID]

        ACCOUNT_GROUP_ID is optional. If not specified, try to remove the filter in report from default account group


        FILTER_NAME list:
        EA  -- Endpoint Agents
        EAL -- Endpoint Agent Labels
        LOC -- Location
        PN  -- Private Network
        NET -- Network
        MN  -- Monitored Network

        Note: when changing filter of Endpoint Agents use agent ID!!
        """
        args = parse_arg(arg)
        if len(args) is 3:
            self.session.params = {}
        elif len(args) is 4:
            self.session.params = {'aid': args[3]}
        else:
            print(self.INVALID_ARGUMENTS_MSG)
            return False

        return self.update_report_filter(args[:3], ReportParser().change_filter_value)

    def do_export_to_acc_group(self, arg):
        """
        Export report from one account group to another account group
        Usage: export_to_acc_group SOURCE_REPORT_ID SOURCE_ACC_GROUP_ID DESTINATION_ACC_GROUP_ID [USERNAME AUTH_TOKEN]

        Note: USERNAME and AUTH_TOKEN are optional if your current account is in the destination account group too
        """
        args = parse_arg(arg)
        if len(args) is 3:
            auth = self.session.auth
        elif len(args) is 5:
            auth = (args[3], args[4])
        else:
            print(self.INVALID_ARGUMENTS_MSG)
            return False

        report_id, src_acc_group_id, dest_acc_group_id = args[:3]

        self.session.params = {'aid': src_acc_group_id}
        report = self.get_report(report_id)
        if report is None:
            return False

        positive_answer = {'yes', 'Yes', 'YES', 'ye', 'Ye', 'Y', 'y', 'yep', 'Yep', 'Yarp', 'yarp'}
        if input('Would you like to rename your export report? [y/n]\n') in positive_answer:
            new_name = input('Please give me the new name you want for the report.\n')
            report['title'] = new_name

        r = requests.post(F'{self.REPORT_API_BASE}/create', params={'aid': dest_acc_group_id}, auth=auth, json=report)

        if r.status_code is 401:
            print('You are not authorised, check your credential for the destination account group.\n')
        elif r is None or r.text is None:
            print('Something went wrong :/\n')
        else:
            print(F'Your report is successfully exported to account group {dest_acc_group_id}!\n')

        self.session.params = {}
        return False

    def get_report(self, report_id: str):
        r = self.session.get(F'{self.REPORT_API_BASE}/{report_id}')
        if not r.ok or r is None or r.text is None:
            print(F'Report with id {report_id} does not exist\n')
            return None
        else:
            return json.loads(r.text)

    def update_report_filter(self, args: list, report_parser_func: Callable[[dict, str, list], dict]) -> bool:
        report_id, filter_code, file_name = args

        raw_report = self.get_report(report_id)
        if raw_report is None:
            return False

        with open(file_name, 'r') as f:
            values = list(map(lambda x: x.strip(), f.read().splitlines()))

        new_report = report_parser_func(raw_report, filter_code.lower(), values)
        if new_report != raw_report:
            self.session.post(F'{self.REPORT_API_BASE}/{report_id}/update', json=new_report)
            print('Done!\n')

        self.session.params = {}
        return False


def parse_arg(arg):
    return arg.split()


if __name__ == '__main__':
    ReportCli().cmdloop()
