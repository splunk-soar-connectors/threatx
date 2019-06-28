import time
from operator import itemgetter
import ipaddress
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult
import requests
import json
from bs4 import BeautifulSoup

# ThreatX Phantom App
# kelly.brazil@threatx.com
# Copyright (c) ThreatX, 2019


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class ThreatxConnector(BaseConnector):

    def __init__(self):

        super(ThreatxConnector, self).__init__()

        self._state = None
        self._base_url = 'https://provision.threatx.io/tx_api/v1'

    def _process_empty_response(self, response, action_result):

        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(action_result.set_status(phantom.APP_ERROR, "Empty response and no information in the header"), None)

    def _process_html_response(self, response, action_result):

        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except:
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code,
                error_text)

        message = message.replace(u'{', '{{').replace(u'}', '}}')

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):

        try:
            resp_json = r.json()
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".format(str(e))), None)

        if 200 <= r.status_code < 399:
            if 'Ok' not in resp_json:
                message = resp_json
                return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

            return RetVal(phantom.APP_SUCCESS, resp_json)

        message = "Error from server. Status Code: {0} Data from server: {1}".format(
                r.status_code, r.text.replace(u'{', '{{').replace(u'}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, r, action_result):

        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': r.status_code})
            action_result.add_debug_data({'r_text': r.text})
            action_result.add_debug_data({'r_headers': r.headers})

        # Process each 'Content-Type' of response separately

        # Process a json response
        if 'json' in r.headers.get('Content-Type', ''):
            return self._process_json_response(r, action_result)

        # Process an HTML response, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if 'html' in r.headers.get('Content-Type', ''):
            return self._process_html_response(r, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not r.text:
            return self._process_empty_response(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
                r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, method="post", commands=None, **kwargs):

        config = self.get_config()

        resp_json = None

        rest_payload = {
            'token': self._state['session_token'],
            'customer_name': config['customer_name']
        }

        if commands is not None:
            rest_payload.update(commands)

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)), resp_json)

        # Create a URL to connect to
        url = self._base_url + endpoint

        try:
            r = request_func(
                            url,
                            verify=config.get('verify_server_cert', False),
                            json=rest_payload,
                            **kwargs)
        except Exception as e:
            return RetVal(action_result.set_status( phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(str(e))), resp_json)

        return self._process_response(r, action_result)

    def _handle_test_connectivity(self, param):

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Add REST commands
        commands = {
            'command': 'list'
        }

        # make rest call
        self.save_progress('Connecting to ThreatX platform...')
        ret_val, response = self._make_rest_call('/users', action_result, commands=commands, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            self.save_progress("Test Connectivity to List Users endpoint Failed.")
            return action_result.get_status()

        # Return success
        self.save_progress("Test Connectivity to List Users endpoint Successful.")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_block_ip(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        commands = {
            'command': 'new_blocklist',
            'entry': {
                'ip': param['ip'],
                'description': 'Added by ThreatX Phantom App',
                'created': int(time.time())
            }
        }

        # Optional values should use the .get() function
        # optional_parameter = param.get('optional_parameter', 'default_value')

        # make rest call
        self.save_progress('Connecting to ThreatX platform...')
        ret_val, response = self._make_rest_call('/lists', action_result, commands=commands, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit

        # Add the response into the data section
        action_result.add_data(response)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['result'] = str(response['Ok'])

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_unblock_ip(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        commands = {
            'command': 'delete_blocklist',
            'ip': param['ip']
        }

        # make rest call
        self.save_progress('Connecting to ThreatX platform...')
        ret_val, response = self._make_rest_call('/lists', action_result, commands=commands, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit

        # Add the response into the data section
        action_result.add_data(response)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['result'] = str(response['Ok'])

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_new_blacklist_ip(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        commands = {
            'command': 'new_blacklist',
            'entry': {
                'ip': param['ip'],
                'description': 'Added by ThreatX Phantom App',
                'created': int(time.time())
            }
        }

        # make rest call
        self.save_progress('Connecting to ThreatX platform...')
        ret_val, response = self._make_rest_call('/lists', action_result, commands=commands, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit

        # Add the response into the data section
        action_result.add_data(response)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['result'] = str(response['Ok'])

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_remove_blacklist_ip(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        commands = {
            'command': 'delete_blacklist',
            'ip': param['ip']
        }

        # make rest call
        self.save_progress('Connecting to ThreatX platform...')
        ret_val, response = self._make_rest_call('/lists', action_result, commands=commands, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit

        # Add the response into the data section
        action_result.add_data(response)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['result'] = str(response['Ok'])

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_new_whitelist_ip(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        commands = {
            'command': 'new_whitelist',
            'entry': {
                'ip': param['ip'],
                'description': 'Added by ThreatX Phantom App',
                'created': int(time.time())
            }
        }

        # make rest call
        self.save_progress('Connecting to ThreatX platform...')
        ret_val, response = self._make_rest_call('/lists', action_result, commands=commands, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit

        # Add the response into the data section
        action_result.add_data(response)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['result'] = str(response['Ok'])

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_remove_whitelist_ip(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        commands = {
            'command': 'delete_whitelist',
            'ip': param['ip']
        }

        # make rest call
        self.save_progress('Connecting to ThreatX platform...')
        ret_val, response = self._make_rest_call('/lists', action_result, commands=commands, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit

        # Add the response into the data section
        action_result.add_data(response)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['result'] = str(response['Ok'])

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_entities(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Optional values should use the .get() function
        # optional_parameter = param.get('optional_parameter', 'default_value')

        commands = {
            'command': 'list',
            'query': {}
        }

        entity_name_param = param.get('entity_name', None)
        entity_id_param = param.get('entity_id', None)
        entity_ip_param = param.get('entity_ip', None)

        if entity_name_param is not None:
            my_entity_name = {'codenames': [entity_name_param]}
            commands['query'].update(my_entity_name)

        if entity_id_param is not None:
            my_entity_id = {'entity_ids': [entity_id_param]}
            commands['query'].update(my_entity_id)

        if entity_ip_param is not None:
            my_entity_ip = {'ip_addresses': [entity_ip_param]}
            commands['query'].update(my_entity_ip)

        # make rest call
        self.save_progress('Connecting to ThreatX platform...')
        ret_val, response = self._make_rest_call('/entities', action_result, commands=commands, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit
        for entity in response['Ok']:
            # Move codename to entity_name
            entity['entity_name'] = entity.pop('codename', None)

            for actor in entity['actors']:
                # Convert actor ip addresses from decimal to dotted-quad strings
                actor['ip_address'] = str(ipaddress.ip_address(actor['ip_address']))

            # Add the response into the data section
            action_result.add_data(entity)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['result'] = str(len(response['Ok'])) + " entities returned."

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_entity_ips(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Optional values should use the .get() function
        # optional_parameter = param.get('optional_parameter', 'default_value')

        commands = {
            'command': 'list',
            'query': {}
        }

        entity_name_param = param.get('entity_name', None)
        entity_id_param = param.get('entity_id', None)
        entity_ip_param = param.get('entity_ip', None)

        if entity_name_param is not None:
            my_entity_name = {'codenames': [entity_name_param]}
            commands['query'].update(my_entity_name)

        if entity_id_param is not None:
            my_entity_id = {'entity_ids': [entity_id_param]}
            commands['query'].update(my_entity_id)

        if entity_ip_param is not None:
            my_entity_ip = {'ip_addresses': [entity_ip_param]}
            commands['query'].update(my_entity_ip)

        # make rest call
        self.save_progress('Connecting to ThreatX platform...')
        ret_val, response = self._make_rest_call('/entities', action_result, commands=commands, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit
        # Convert actor ip addresses from decimal to dotted-quad strings and add to the result data
        for entity in response['Ok']:
            for actor in entity['actors']:
                action_result.add_data({'entity_name': str(entity['codename']),
                                        'entity_id': str(entity['id']),
                                        'ip': str(ipaddress.ip_address(actor['ip_address'])),
                                        'geo_country': str(actor['geo_country'])
                                        })

        summary = action_result.update_summary({})
        summary['result'] = str(action_result.get_data_size()) + " IPs returned."

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_entity_risk(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        commands = {
            'command': 'risk_changes',
            'id': param['entity_id']
        }

        # make rest call
        self.save_progress('Connecting to ThreatX platform...')
        ret_val, response = self._make_rest_call('/entities', action_result, commands=commands, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit
        # add pretty_time key to result
        response['Ok'][-1]['pretty_time'] = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(response['Ok'][-1]['timestamp']))

        # Add the response into the data section
        # Grab the last risk score of the entity
        action_result.add_data(response['Ok'][-1])

        summary = action_result.update_summary({})
        summary['result'] = "Entity " + str(param['entity_id']) + " risk is " + str(response['Ok'][-1]['risk'])

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_entity_notes(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        commands = {
            'command': 'notes',
            'id': param['entity_id']
        }

        # make rest call
        self.save_progress('Connecting to ThreatX platform...')
        ret_val, response = self._make_rest_call('/entities', action_result, commands=commands, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit
        # Add readable format dates
        for note in response['Ok']:
            note['pretty_time'] = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(note['timestamp']))

        # Reverse sort the list by timestamp
        response['Ok'] = sorted(response['Ok'], key=itemgetter('timestamp'), reverse=True)

        # Add the response into the data section
        for record in response['Ok']:
            action_result.add_data(record)

        summary = action_result.update_summary({})
        summary['result'] = str(action_result.get_data_size()) + " notes returned for Entity ID " + str(param['entity_id']) + "."

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_new_entity_note(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        commands = {
            'command': 'new_note',
            'note': {
                'entity_id': param['entity_id'],
                'content': param['content']
            }
        }

        # make rest call
        self.save_progress('Connecting to ThreatX platform...')
        ret_val, response = self._make_rest_call('/entities', action_result, commands=commands, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit

        # Add the response into the data section
        action_result.add_data(response)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['result'] = str(response['Ok'])

        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        elif action_id == 'block_ip':
            ret_val = self._handle_block_ip(param)

        elif action_id == 'unblock_ip':
            ret_val = self._handle_unblock_ip(param)

        elif action_id == 'new_blacklist_ip':
            ret_val = self._handle_new_blacklist_ip(param)

        elif action_id == 'remove_blacklist_ip':
            ret_val = self._handle_remove_blacklist_ip(param)

        elif action_id == 'new_whitelist_ip':
            ret_val = self._handle_new_whitelist_ip(param)

        elif action_id == 'remove_whitelist_ip':
            ret_val = self._handle_remove_whitelist_ip(param)

        elif action_id == 'get_entities':
            ret_val = self._handle_get_entities(param)

        elif action_id == 'get_entity_ips':
            ret_val = self._handle_get_entity_ips(param)

        elif action_id == 'get_entity_risk':
            ret_val = self._handle_get_entity_risk(param)

        elif action_id == 'get_entity_notes':
            ret_val = self._handle_get_entity_notes(param)

        elif action_id == 'new_entity_note':
            ret_val = self._handle_new_entity_note(param)

        return ret_val

    def initialize(self):
        self.save_progress('Initializing request...')

        def _txlogin():
            _url = self._base_url + '/login'
            login_payload = {
                'command': 'login',
                'api_token': config['api_key']
            }
            try:
                r = requests.post(_url, json=login_payload, timeout=10)
            except Exception as e:
                return self.set_status(phantom.APP_ERROR, status_message="Error : {}".format(str(e)))
            # error check
            if r.status_code != 200:
                self._state['token_expires'] = None
                self._state['session_token'] = None
                message = 'Received status code ' + str(r.status_code) + ' from server during login. Clearing session token cache.'
                return self.set_status(phantom.APP_ERROR, status_message=message)

            response = r.json()

            if 'Ok' in response:
                if response['Ok']['status'] is False:
                    self._state['token_expires'] = None
                    self._state['session_token'] = None
                    message = 'Invalid credentials during login. Clearing session token cache.'
                    return self.set_status(phantom.APP_ERROR, status_message=message)
            else:
                self._state['token_expires'] = None
                self._state['session_token'] = None
                message = 'Cannot parse login response. Clearing session token cache.'
                return self.set_status(phantom.APP_ERROR, status_message=message)

            # set the API Session Token and reset the API Session Token expiration timer for 10 minutes
            self._state['session_token'] = response['Ok']['token']
            self._state['token_expires'] = int(time.time() + (10 * 60))
            self.save_progress('Cached new session token.')
            return phantom.APP_SUCCESS

        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        if 'session_token' not in self._state:
            self._state['session_token'] = None

        if 'token_expires' not in self._state:
            self._state['token_expires'] = None

        # get the asset config
        config = self.get_config()

        if self._state['session_token'] is None:
            self.save_progress('Session token missing - getting new session token...')
            return _txlogin()
        else:
            self.save_progress('Using cached session token.')

        if self._state['session_token'] is not None:
            if self._state['token_expires'] < int(time.time()):
                self.save_progress('Session token expired - getting new session token...')
                return _txlogin()
            else:
                self.save_progress('Cached session token not expired.')
                return phantom.APP_SUCCESS

        # Catch any other errors
        self._state['token_expires'] = None
        self._state['session_token'] = None
        return self.set_status_save_progress(phantom.APP_ERROR, status_message='An error occurred during login. Clearing session token cache.')

    def finalize(self):

        # Save the state, this data is saved across actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


if __name__ == '__main__':

    import pudb
    import argparse

    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if (username is not None and password is None):

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if (username and password):
        try:
            login_url = ThreatxConnector._get_phantom_base_url() + '/login'

            print ("Accessing the Login page")
            r = requests.get(login_url, verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = login_url

            print ("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print ("Unable to get session id from the platform. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = ThreatxConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)
