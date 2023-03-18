# path for new modules /opt/so/conf/elastalert/modules/custom/

# -*- coding: utf-8 -*-

from time import gmtime, strftime
import requests,json,urllib.parse
from elastalert.alerts import Alerter

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class D0g3N0t1fy(Alerter):
  """
  build webhook alert based on info in observation
  """
  required_options = set(['event.fields', 'subject_args', 'webhook_url'])

  def alert(self, matches):
    for match in matches:
      today = strftime("%Y.%m.%d", gmtime())
      timestamp = strftime("%Y-%m-%d"'T'"%H:%M:%S"'.000Z', gmtime())
      headers = {"Content-Type": "application/json"}
      creds = None
      if 'es_username' in self.rule and 'es_password' in self.rule:
        creds = (self.rule['es_username'], self.rule['es_password'])
    # sending webhook
    def send_message(message, description):
      headers = {
        'Conten-Type': 'application/json'
      }
      webhook_url = self.rule['discord_webhook_url']
      payload = {
        "content": message,
        "embeds": [
          {
            "description": description
          }
        ]
      }
      
      payload = {
        "content": message,
        "embeds": [
          {
            "description": description
          }
        ]
      }
      response = requests.post(webhook_url, headers=headers, json=payload)

      if response.status_code != 204:
        raise ValueError("Webhook request failed")      
    
    # function for creating webhook message
    def create_payload(obs, subjectArgs, searchFields):

      # set subject line
      if subjectArgs:
        subject = ''
        if len(subjectArgs) > 1:
          addColon = True
        else:
          addColon = False
        for field in subjectArgs:
          if '.' in field:
            field = field.split('.')
            value = dict_loop(obs, field)
            if not value: # break if can't find value
              addColon = False
              continue
            subject = subject + f"{value}"
            if addColon:
              subject = subject + " : "
              addColon = False
          else:
            try:
              subject = subject + f"{obs[field]}"
            except Exception as e:
              exception = f"{type(e).__name__}: {e}"
              print(f"{exception}")
              addColon = False
              continue
            if addColon:
              subject = subject + " : "
              addColon = False

      message_contents = "Event Details:"
      if searchFields:
        for field in searchFields:
          if '.' in field:
            fields = field.split('.')
            value = dict_loop(obs, fields)
            if value:
              message_contents = message_contents + f"\n{' '.join(fields).title()} : {value}"
          else:
            try:
              message_contents = message_contents + f"\n{field.title()} : {obs[field]}"
            except Exception as e:
                exception = f"{type(e).__name__}: {e}"
                print(f"{exception}")
            continue   
      # add links
      if 'hunt_link' in obs.keys():
        message_contents = message_contents + "\n" + f"[Hunt Link]({obs.get('hunt_link')})"
      elif 'network' in obs.keys() and 'community_id' in obs['network'].keys():
        link_fields = ['network.community_id']
        # to-do: add link to message_contents
        message_contents = message_contents + "\n" + f"[Hunt Link](https://sec-manager.w3legue.com/#/hunt?q={create_link(obs, link_fields)})"
      else:
        if '@timestamp' in searchFields:
          link_fields = searchFields
          link_fields.remove('@timestamp')
        # to-do: add link to message_contents
        else:
          link_fields = searchFields
        message_contents = message_contents + "\n" + f"[Hunt Link](https://sec-manager.w3legue.com/#/hunt?q={create_link(obs, link_fields)})"

      return subject, message_contents 

    # function for looping through nested dictionary objects
    def dict_loop(obs, search):
      temp = obs
      for i in search:
        try:
          temp = temp[i]
        except Exception as e:
          exception = f"{type(e).__name__}: {e}"
          print(f"{exception}")
      if type(temp) is dict:
        temp = False
      return temp

    # creates hunt link
    def create_link(obs, filters):
      linkList = []
      linkString = ''
      for field in filters:
        try:
          if '.' in field:
            field = field.split('.')
            temp = obs
            for num in range(len(field)):
              temp = temp[field[num]] # todo add check for non-exist field
            linkList.append(temp)
          else:
            linkList.append(obs[field])          
        except Exception as e:
          exception = f"{type(e).__name__}: {e}"
          print(f"{exception}")

      for item in linkList:
        if len(linkString) == 0:
          linkString = f'"{item}"'
        else:
          linkString = linkString + f' OR "{item}"'
      linkString = '('+linkString+')'+' | groupby "event.module" "event.dataset"'
      linkString = urllib.parse.quote(linkString)
      return linkString
  
    send_message(*create_payload(match, self.rule['subject_args'], self.rule['event.fields']))

  def get_info(self):
    return {'type': 'D0g3N0t1fy'}
