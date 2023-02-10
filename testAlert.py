import requests, urllib.parse
#test_obs = {"@timestamp":"2023-02-10T01:51:41.561Z","@version":"1","client.bytes":24762000,"client.ip":"172.17.40.29","client.ip_bytes":44023592,"client.packets":687914,"client.port":"46933","connection.bytes.missed":0,"connection.history":"Dd","connection.local.originator":"true","connection.local.responder":"true","connection.state":"SF","connection.state_description":"Normal SYN/FIN completion","destination.ip":"172.17.20.190","destination.port":27031,"ecs.version":"8.0.0","event.category":"network","event.dataset":"conn","event.duration":8880.760611057281,"event.ingested":"2023-02-10T04:20:43.543Z","event.module":"zeek","log.file.path":"/nsm/zeek/logs/current/conn.log","log.id.uid":"Cgzhg64A8OUVi5czNe","log.offset":3731913,"message":"{\"ts\":1675993901.561562,\"uid\":\"Cgzhg64A8OUVi5czNe\",\"id.orig_h\":\"172.17.40.29\",\"id.orig_p\":46933,\"id.resp_h\":\"172.17.20.190\",\"id.resp_p\":27031,\"proto\":\"udp\",\"duration\":8880.760611057281,\"orig_bytes\":24762000,\"resp_bytes\":151372803840,\"conn_state\":\"SF\",\"local_orig\":"true",\"local_resp\":"true",\"missed_bytes\":0,\"history\":\"Dd\",\"orig_pkts\":687914,\"orig_ip_bytes\":44023592,\"resp_pkts\":106950464,\"resp_ip_bytes\":154367416832,\"community_id\":\"1:nq/MQVgQQ0XwKqsVriWPOaP2+jc=\"}","metadata.beat":"filebeat","metadata.ip_address":"172.17.5.7","metadata.type":"_doc","metadata.version":"8.4.3","network.bytes":151397565840,"network.community_id":"1:nq/MQVgQQ0XwKqsVriWPOaP2+jc=","network.transport":"udp","observer.name":"sec-sniff","server.bytes":151372803840,"server.ip":"172.17.20.190","server.ip_bytes":154367416832,"server.packets":106950464,"server.port":"27031","source.ip":"172.17.40.29","source.port":46933,"tags":["beats_input_codec_plain_applied"],"soc_id":"rlqNOYYBgYTNIJ1O5zAy","soc_score":13.062379,"soc_type":"","soc_timestamp":"2023-02-10T01:51:41.561Z","soc_source":"sec-manager:so-zeek-2023.02.10"}
dhcp_alert = {"@timestamp":"2023-02-10T01:32:56.656Z","client.address":"172.17.40.62","event.dataset":"alert","event.module":"d0g3alert","event.severity":3,"event.severity_label":"high","event.timestamp":"2023-02-10T01:34:08.000Z","host.hostname":"ESP_10CC5F","host.mac":"50:02:91:10:cc:5f","rule.category":"dhcp","rule.name":"New DHCP Client Found","rule.uuid":"000001","soc_id":"Hlj1OIYBgYTNIJ1OV1to","soc_score":6.043156,"soc_type":"","soc_timestamp":"2023-02-10T01:32:56.656Z","soc_source":"sec-manager:so-d0g3alert-alerts-2023.02.10"}
alert_obs = {"@timestamp":"2023-02-10T02:24:35.095Z","@version":"1","destination.ip":"172.17.40.29","destination.port":46933,"ecs.version":"8.0.0","event.category":"network","event.dataset":"alert","event.ingested":"2023-02-10T02:24:44.949Z","event.module":"suricata","event.severity":3,"event.severity_label":"high","host.name":"sec-sniff","log.file.path":"/nsm/suricata/eve-2023-02-10-02:19.json","log.id.uid":"275151227556331","log.offset":88780,"metadata.beat":"filebeat","metadata.ip_address":"172.17.5.7","metadata.type":"_doc","metadata.version":"8.4.3","network.community_id":"1:nq/MQVgQQ0XwKqsVriWPOaP2+jc=","network.transport":"UDP","observer.name":"sec-sniff","rule.action":"allowed","rule.category":"Attempted Administrator Privilege Gain","rule.gid":1,"rule.metadata.attack_target":["Server"],"rule.metadata.created_at":["2021_12_12"],"rule.metadata.cve":["CVE_2021_44228"],"rule.metadata.deployment":["Internal","Perimeter"],"rule.metadata.former_category":["EXPLOIT"],"rule.metadata.signature_severity":["Major"],"rule.metadata.tag":["Exploit"],"rule.metadata.updated_at":["2022_01_11"],"rule.name":"ET EXPLOIT Possible Apache log4j RCE Attempt - 2021/12/12 Obfuscation Observed M2 (udp) (CVE-2021-44228)","rule.reference":"https://doc.emergingthreats.net/2034674","rule.rev":2,"rule.rule":"alert udp any any -> [$HOME_NET,$HTTP_SERVERS] any (msg:\"ET EXPLOIT Possible Apache log4j RCE Attempt - 2021/12/12 Obfuscation Observed M2 (udp) (CVE-2021-44228)\"; content:\"|24 7b|\"; content:\"|24 7b 3a 3a|\"; within:100; fast_pattern; reference:cve,2021-44228; classtype:attempted-admin; sid:2034674; rev:2; metadata:attack_target Server, created_at 2021_12_12, cve CVE_2021_44228, deployment Perimeter, deployment Internal, former_category EXPLOIT, signature_severity Major, tag Exploit, updated_at 2022_01_11;)","rule.ruleset":"Emerging Threats","rule.severity":1,"rule.uuid":"2034674","source.ip":"172.17.20.190","source.port":27031,"tags":["beats_input_codec_plain_applied"],"soc_id":"ZVkjOYYBgYTNIJ1OuxZI","soc_score":5.028929,"soc_type":"","soc_timestamp":"2023-02-10T02:24:35.095Z","soc_source":"sec-manager:so-ids-2023.02.10"}
dhcpLong = {"@timestamp": "2023-02-10T01:32:56.656Z","client": {"address": "172.17.40.62"},"event": {"dataset": "alert","module": "d0g3alert","severity": 3,"severity_label": "high","timestamp": "2023-02-10T01:34:08.000Z"},"host": {"hostname": "ESP_10CC5F","mac": "50:02:91:10:cc:5f"},"rule": {"category": "dhcp","name": "New DHCP Client Found","uuid": "000001"},"soc_id": "Hlj1OIYBgYTNIJ1OV1to","soc_score": 6.043156,"soc_type": "","soc_timestamp": "2023-02-10T01:32:56.656Z","soc_source": "sec-manager:so-d0g3alert-alerts-2023.02.10"}
webhook_url = "https://discord.com/api/webhooks/951933565803839558/MEOJ2jeeHbB1DVFAsR9LA_QWNlWCSRPDW3mdLBWJ-Ytlnyhp-AdVEhuElKxpK8cbpdIO"

event_fields = ['@timestamp', 'client.address', 'host.hostname']
subjectLine = ['event.severity_label', 'rule.name']

def send_message(message, description):
  headers = {
    'Conten-Type': 'application/json'
  }
  webhook_url = "https://discord.com/api/webhooks/951933565803839558/MEOJ2jeeHbB1DVFAsR9LA_QWNlWCSRPDW3mdLBWJ-Ytlnyhp-AdVEhuElKxpK8cbpdIO"
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
        subject = subject + f"{dict_loop(obs, field)}"
        if addColon:
          subject = subject + " : "
          addColon = False
      else:
        subject = subject + f"{field}"
        if addColon:
          subject = subject + " : "
          addColon = False

  message_contents = "Event Details:"
  if searchFields:
    for field in searchFields:
      message_contents = message_contents + "\n" + f"{field} : "
      if '.' in field:
        field = field.split('.')
        message_contents = message_contents + f"{dict_loop(obs, field)}"
      else:
        try:
          message_contents = message_contents + f"{obs.get(field)}"
        except Exception as e:
            exception = f"{type(e).__name__}: {e}"
            print(f"{exception}")
        continue
  
  if 'hunt_link' in obs.keys():
    message_contents = message_contents + "\n" + f"[Hunt Link](https://sec-manager.w3legue.com/#/hunt?q={obs.get('hunt_link')})"
  elif 'network' in obs.keys() and 'community_id' in obs['network'].keys():
    link_fields = ['network.community_id']
    # to-do: add link to message_contents
    message_contents = message_contents + "\n" + f"[Hunt Link](https://sec-manager.w3legue.com/#/hunt?q={create_link(obs, link_fields)})"
  else:
    if '@timestamp' in searchFields:
      link_fields = searchFields
      link_fields.remove('@timestamp')
    # to-do: add link to message_contents
    message_contents = message_contents + "\n" + f"[Hunt Link](https://sec-manager.w3legue.com/#/hunt?q={create_link(obs, link_fields)})"

  return subject, message_contents

def dict_loop(dict, search):
  temp = dict
  for i in search:
    temp = temp[i]
  return temp

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


send_message(*create_payload(dhcpLong, subjectLine, event_fields))
