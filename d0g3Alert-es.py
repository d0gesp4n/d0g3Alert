# path for new modules /opt/so/conf/elastalert/modules/custom/

# -*- coding: utf-8 -*-

from time import gmtime, strftime
import requests,json,urllib.parse
from elastalert.alerts import Alerter

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class D0g3Alert(Alerter):
  """
  Use matched data to create alerts in elasticsearch
  """
  required_options = set(['rule_title','rule_id','rule_category','rule_severity'])

  def alert(self, matches):
    for match in matches:
      today = strftime("%Y.%m.%d", gmtime())
      timestamp = strftime("%Y-%m-%d"'T'"%H:%M:%S"'.000Z', gmtime())
      headers = {"Content-Type": "application/json"}

      creds = None
      if 'es_username' in self.rule and 'es_password' in self.rule:
        creds = (self.rule['es_username'], self.rule['es_password'])
      
      # set rule_level
      alert_severity = self.rule['rule_severity']
      if alert_severity == 4:
        rule_level = 'critical'
      elif alert_severity == 3:
        rule_level = 'high'
      elif alert_severity == 2:
        rule_level = 'medium'
      else:
        rule_level == 'low'
      
      # set event fields
      if 'event.dataset' in self.rule.keys():
        event_dataset = self.rule['event.dataset']
      else:
        event_dataset = 'alert'
      if 'event.module' in self.rule.keys():
        event_module = self.rule['event.module']
      else:
        event_module = 'd0g3alert'
      
      payload = {
        "rule": {
          "name": self.rule['rule_title'],
          "uuid": self.rule['rule_id'],
          "category": self.rule['rule_category'] 
          },
        "event":{
          "dataset": event_dataset,
          "module": event_module,
          "severity": self.rule['rule_severity'],
          "severity_label": rule_level,
          "timestamp": timestamp 
          }
      }
      
      # grab mitre fields
      def setMitreFields():
        mitre_dict = {'rule':{'mitre':{}}}
        if 'mitre.id' and 'mitre.name' in self.rule.keys():
          mitre_dict['rule']['mitre'].update({'id': self.rule['mitre.id']})          
          mitre_dict['rule']['mitre'].update({'technique': self.rule['mitre.name']})          
          return mitre_dict
        else:
          return
      
      def createDictionary(obs, searchFields):
        output_dict = {}
        for field in searchFields:
          if '.' in field:
            field = field.split('.')
          else:
            try:
              output_dict[field] = obs[field]
            except Exception as e:
              exception = f"{type(e).__name__}: {e}"
              print(f"{exception}")
            continue

          if field[0] in output_dict.keys():
            try:
              output_dict[field[0]].update({field[1]: obs[field[0]][field[1]]})
            except Exception as e:
              exception = f"{type(e).__name__}: {e}"
              print(f"{exception}")
          else:
            try:
              output_dict[field[0]] = {field[1]: obs[field[0]][field[1]]}
            except Exception as e:
              exception = f"{type(e).__name__}: {e}"
              print(f"{exception}")

        return output_dict
      
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
      
      # set additional payload fields
      if 'link_filters' in self.rule.keys():
        payload.update({'hunt_link': 'https://sec-manager.w3legue.com/#/hunt?q='+create_link(
          match, self.rule['link_filters'])})
      
      if 'event_fields' in self.rule.keys():
        payload.update(createDictionary(match, self.rule['event_fields']))
      else:
        payload.update(match)
      
      if 'mitre.id' and 'mitre.name' in self.rule.keys():
        payload.update(setMitreFields())
      # set ES url
      url = f"https://{self.rule['es_host']}:{self.rule['es_port']}/so-d0g3alert-alerts-{today}/_doc/"
      # post to ES index
      requests.post(url, data=json.dumps(payload), headers=headers, verify=False, auth=creds)

  def get_info(self):
    return {'type': 'D0g3Alert'}
