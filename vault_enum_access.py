#!/usr/bin/env python

import argparse
import os
import hvac


class Program:
    args = None
    client = None
    parser = argparse.ArgumentParser(description="Enumerates access to a given Vault secret path")

    @staticmethod
    def main():
        program = Program()
        program.run()

    def run(self):
        self.add_arguments_and_parse()
        if 'VAULT_ADDR' not in os.environ or 'VAULT_TOKEN' not in os.environ:
            print("ERROR: Either VAULT_ADDR or VAULT_TOKEN is not set in environment.")
            exit(1)

        vault_addr = os.environ['VAULT_ADDR']
        vault_token = os.environ['VAULT_TOKEN']
        verify = os.environ['VERIFY_CERT'] if 'VERIFY_CERT' in os.environ else False

        self.client = hvac.Client(
            url=vault_addr,
            token=vault_token,
            verify=verify
        )

        if self.client.is_authenticated():
            print(f"Enumerating access to:\n\t{self.args.path} on\n\t{vault_addr}\n")
            paths = self.parse_paths()
            matching_policies = self.find_matching_policies(paths)
            print(f"Found these matching policies:\n\t{matching_policies}\n")
            ldap_groups = self.find_ldap_groups_tied_to_policies(matching_policies)
            print(f"Found these ldap groups tied to one or more of the matching policies:\n\t{ldap_groups}\n")
            iam_roles = self.find_aws_iam_roles_tied_to_policies(matching_policies)
            print(f"Found these AWS iam roles tied to one or more of the matching policies:\n\t{iam_roles}\n")
        else:
            print(f"Not authenticated")

    def parse_paths(self):
        """
        Parses the Vault path e.g. secrets/foo/bar and generates a list containing glob paths that would include it
        :returns: ['*', 'secrets/*', 'secrets/foo/*', 'secrets/foo/bar']
        """
        path = self.args.path
        paths = ['*']  # The everything glob
        sub_path = ''
        for part in path.split('/')[0:-1]:
            sub_path += f"{part}/"
            paths.append(f"{sub_path}*")  # The in-between globs
        paths.append(f"{path}")  # The full path
        return paths

    def find_matching_policies(self, paths):
        """
        Finds policies with read access to a list of paths
        :param paths: the list of glob paths that are relevant
        :return: the list of policies that have read access to any of the paths
        """
        matching_policies = []
        print(f"Looking for policies that provide read or sudo access to:\n\t{paths}\n")

        all_policies = self.client.sys.list_policies()['policies']
        for policy_name in all_policies:
            policy = self.client.get_policy(policy_name, parse=True)
            statements = dict(policy['path'] if 'path' in policy else dict())
            for path in statements.keys():
                capabilities = statements[path]['capabilities'] if 'capabilities' in statements[path] else []
                if ('read' in capabilities or 'sudo' in capabilities) and path in paths:
                    matching_policies.append(policy_name)

        return matching_policies

    def find_ldap_groups_tied_to_policies(self, policies):
        """
        Finds ldap groups tied to the specified policies
        :param policies: the list of policies to look for
        :return: the list of ldap groups tied to the specified policies
        """
        linked_groups = []
        set_of_policies = set(policies)
        ldap_group_names = self.client.auth.ldap.list_groups()['data']['keys']
        for ldap_group_name in ldap_group_names:
            set_of_linked_policies = set(self.client.auth.ldap.read_group(ldap_group_name)['data']['policies'])
            matching_policies = set_of_linked_policies & set_of_policies
            if matching_policies:
                linked_groups.append(ldap_group_name)
        return linked_groups

    def find_aws_iam_roles_tied_to_policies(self, policies):
        """
        Finds AWS IAM roles tied to the specified policies
        :param policies: the list of policies to look for
        :return: the list of IAM roles tied to the specified policies
        """
        linked_iam_roles = []
        set_of_policies = set(policies)
        iam_role_names = self.client.auth.aws.list_roles()['keys']
        for iam_role_name in iam_role_names:
            iam_role = self.client.auth.aws.read_role(iam_role_name)
            bound_iam_principal_arn = iam_role['bound_iam_principal_arn'] if 'bound_iam_principal_arn' in iam_role else ''
            set_of_linked_policies = set(iam_role['policies'] if 'policies' in iam_role else [])
            matching_policies = set_of_linked_policies & set_of_policies
            if matching_policies and bound_iam_principal_arn:
                linked_iam_roles.append(bound_iam_principal_arn)
        return linked_iam_roles

    def add_arguments_and_parse(self):
        self.parser.add_argument("--path", dest="path", required=True,
                                 help="The path of the secret in Vault. e.g. secrets/foo/bar")
        self.args = self.parser.parse_args()


def main():
    Program.main()


if __name__ == "__main__":
    main()
