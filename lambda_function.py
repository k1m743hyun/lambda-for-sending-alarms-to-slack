# 사용 중인 표준 라이브러리
import os
import re
import sys
import json
import boto3
import logging
import datetime
from base64 import b64decode
from urllib import request, error

# 사용 중인 서드파티 라이브러리
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'packages'))
from jira import JIRA


# 암호화된 Jira Token을 복호화하는 코드
for var in ['kmsEncryptedJiraToken', 'kmsEncryptedKeyId']:
    globals()['DECRYPTED_{}'.format(var.replace('kmsEncrypted', '').upper())] = boto3.client('kms').decrypt(
        CiphertextBlob=b64decode(os.environ[var]),
        EncryptionContext={'LambdaFunctionName': os.environ['AWS_LAMBDA_FUNCTION_NAME']}
    )['Plaintext'].decode('utf-8')

# JSON 파일을 읽어서 전역 변수로 자동 생성
for filename in os.listdir('json'):
    if filename.split('.')[0]:
        with open('json/{}'.format(filename), 'r') as json_file:
            globals()['{}_INFO'.format(filename.split('.')[0].upper())] = json.load(json_file)
        
# logging을 위해 선언한 코드
LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)


# UTC Timezone이 적용된 Datetime을 KST Timezone으로 변환하기 위한 함수
def convert_kst(timestamp):
    # 9시간을 더하는 코드
    timestring = str(datetime.datetime.strptime(timestamp.split('.')[0], '%Y-%m-%dT%H:%M:%S') - datetime.timedelta(hours=-9))

    # 날짜 추출
    date = timestring.split(' ')[0].split('-')

    # 시간 추출
    time = timestring.split(' ')[1].split(':')

    return date, time


# AssumeRole을 사용하여 Cross Account 권한을 얻는 함수
def get_client(instance, role_arn):
    # sts:assume_role을 사용하여 권한을 얻는 코드
    sts_client = boto3.client('sts')
    assumed_role_object = sts_client.assume_role(
        RoleArn=role_arn,
        RoleSessionName='AssumeRoleSession'
    )

    # Token 값 추출
    credentials = assumed_role_object['Credentials']
    accesskey = credentials['AccessKeyId']
    secretkey = credentials['SecretAccessKey']
    session_token = credentials['SessionToken']

    # resource에 접근하는 코드
    client = boto3.client(
        instance,
        aws_access_key_id=accesskey,
        aws_secret_access_key=secretkey,
        aws_session_token=session_token,
    )

    return client


# 알람 이벤트를 정의한 클래스
class AlarmEvent:
    # 생성자
    def __init__(self, event):
        # 초기값
        self.format = None
        self.env_dict = {}

        # event에서 데이터 추출
        self.title = event['Records'][0]['Sns']['Subject']
        self.message = event['Records'][0]['Sns']['Message']
        self.timestamp = event['Records'][0]['Sns']['Timestamp']
        self.topic_arn = event['Records'][0]['Sns']['TopicArn']

        # message가 JSON 형식인지 아닌지 확인하는 코드
        try:
            self.message = json.loads(self.message)
        except json.decoder.JSONDecodeError:
            LOGGER.info("This Alarm does NOT fit the JSON Format")

    # S3에 업로드하기 위한 함수
    def upload_s3(self, s3_data, s3_bucket, s3_path):
        boto3.client('s3').put_object(
            Body=s3_data,
            Bucket=s3_bucket,
            Key=s3_path,
            ServerSideEncryption="aws:kms",
            SSEKMSKeyId=globals().get('DECRYPTED_KEYID')
        )


# CloudWatch 발생한 알람 event를 정의한 클래스
class CloudwatchAlarm(AlarmEvent):
    # 생성자
    def __init__(self, event):
        # 부모 클래스 생성자 호출
        super().__init__(event)

        # message에서 데이터 추출
        self.alarm_name = self.message['AlarmName']
        self.alarm_desc = self.message['AlarmDescription']
        self.account_id = self.message['AWSAccountId']
        self.new_state = self.message['NewStateValue']
        self.reason = self.message['NewStateReason']
        self.region = self.message['Region']
        self.alarm_arn = self.message['AlarmArn']
        self.old_state = self.message['OldStateValue']
        self.trigger = self.message['Trigger']

        # 위에서 추출한 데이터를 이용하여 새로운 데이터 생성
        self.target = '--'.join(self.alarm_name.split('--')[:-2])
        self.metric = self.alarm_name.split('--')[-2]
        self.resource = self.alarm_name.split('--')[-1]
        self.instance_type = [pattern for pattern in globals()['AWS_INFO']['type'] if re.compile(pattern).match(self.target.split('-')[0])][-1] if globals()['AWS_INFO']['type'].get(self.target.split('-')[0]) else globals()['AWS_INFO']['type'].get(self.target.split('-')[0])
        self.dimensions = self.trigger.get('Dimensions')
        self.node_name = [dimension['value'] for dimension in self.dimensions if dimension['name'] == 'NodeName']

        # metric 데이터가 METRIC_INFO에 없는 경우 None으로 정의
        try:
            # 모든 리소스를 JSON에 입력할 수 없기에 리소스를 구분할 수 있는 정규식을 Key로 하였으며, 해당 Target 리소스가 해당하는 정규식 Key를 찾는 코드
            self.target_pattern = [p for p in globals()['METRIC_INFO'][self.metric] if re.compile(p).search(self.target)][0]
            self.category = globals()['METRIC_INFO'][self.metric][self.target_pattern]['jira_epic'].split(' ')[1]
            self.error_level = globals()['METRIC_INFO'][self.metric][self.target_pattern]['error_level']
            self.error_effect = globals()['METRIC_INFO'][self.metric][self.target_pattern]['error_effect']
            self.jira_epic = globals()['METRIC_INFO'][self.metric][self.target_pattern]['jira_epic']
            self.slack_channel = globals()['METRIC_INFO'][self.metric][self.target_pattern]['slack_channel']
        except Exception as e:
            self.target_pattern = None
            self.category = None
            self.error_level = None
            self.error_effect = None
            self.jira_epic = None
            self.slack_channel = None
        self.level_comment = globals()['LEVEL_INFO'].get(self.error_level)
        self.priority = 'High' if self.error_level in ['1급', '2급', '3급'] else 'Medium'

    # AWS CloudWatch에서 해당 metric에 대한 세부 정보를 얻어와 S3에 업로드하는 함수
    def upload_s3(self, **kwargs):
        # S3에 업로드하기 위해 필요한 데이터 선언
        s3_data = None
        s3_bucket = globals()['AWS_INFO']['s3']['bucket']
        dir_name = globals()['AWS_INFO']['account'][self.account_id] if self.account_id.isdigit() else self.account_id
        file_name = '{alarm_name}--{timestamp}'.format(alarm_name=self.alarm_name, timestamp=self.timestamp)
        s3_path = '{dir_name}/{file_name}.csv'.format(dir_name=dir_name, file_name=file_name)

        # 알람 발생 15분 전을 시작 시간으로 알람 발생 시간을 종료 시간으로 설정
        timestamp = datetime.datetime.strptime(self.timestamp.split('.')[0], '%Y-%m-%dT%H:%M:%S')
        start_time = timestamp - datetime.timedelta(minutes=15)
        end_time = timestamp

        # CloudWatch에서 get_metric_data를 수행하려면 message 내의 trigger 데이터가 필요
        if self.trigger:
            # trigger에서 데이터 추출
            namespace = self.trigger.get('Namespace')
            metric_name = self.trigger.get('MetricName')
            dimensions = [{str.capitalize(key): val for key, val in dim.items()} for dim in self.trigger.get('Dimensions')]
            period = self.trigger.get('Period')
            statistic = self.trigger.get('Statistic').capitalize()
            cw_client = get_client('cloudwatch', os.environ['acc_network'])

            # CloudWatch에서 받은 metric 데이터 저장
            response = cw_client.get_metric_data(
                MetricDataQueries=[
                    {
                        'Id': 'getMetricData',
                        'MetricStat': {
                            'Metric': {
                                'Namespace': namespace,
                                'MetricName': metric_name,
                                'Dimensions': dimensions
                            },
                            'Period': period,
                            'Stat': statistic,
                        },
                        'ReturnData': True,
                    },
                ],
                StartTime=start_time,
                EndTime=end_time,
            )

            # CloudWatch에서 받은 값을 csv 형식으로 변환
            s3_data = '\n'.join(['Timestamp,Value'] + ['{},{}'.format(t, v) for c in response['MetricDataResults'] for t, v in zip(c['Timestamps'], c['Values'])])

        # 부모 클래스의 메소드 호출
        super().upload_s3(str(s3_data), s3_bucket, s3_path)

        # S3에 저장된 CSV 파일 링크 생성
        s3_link = 'https://{s3_bucket}.s3.ap-northeast-2.amazonaws.com/{dir_name}/{file_name}.csv'.format(s3_bucket=s3_bucket, dir_name=dir_name, file_name=file_name)

        return s3_link

    # 알람이 발생한 resource name에서 env를 추출하는 함수
    def get_environment(self):
        return {globals().get('ENVIRONMENT_INFO')[e]['code']: globals().get('ENVIRONMENT_INFO')[e]['word'] for e in globals().get('ENVIRONMENT_INFO') if re.compile(e).search(self.target.split('-')[3])}

    # 알람 메세지를 생성하는 함수
    def make_message(self, env):
        # UTC를 KST로 변환하는 함수 호출
        date, time = convert_kst(self.timestamp)

        # 알람 메세지 포맷에 맞춰서 데이터 입력
        content_lines = [
            "[ {env} / {category} / {instance_type} / {resource} 장애 발생 ]".format(env=env[0], category=self.category, instance_type=self.instance_type, resource=self.resource),
            "장애 레벨: {error_level}({level_comment})".format(error_level=self.error_level, level_comment=self.level_comment),
            "장애 영향: {error_effect}".format(error_effect=self.error_effect),
            "장애 대상: {target}({node_name})".format(target=self.target, node_name=self.node_name[0]) if self.node_name else "장애 대상: {target}".format(target=self.target),
            "장애 메트릭: {metric}".format(metric=self.metric),
            "장애 내용:",
            "- Name: {alarm_name} / in {region}".format(alarm_name=self.alarm_name, region=self.region),
            "- Description: {alarm_desc}".format(alarm_desc=self.alarm_desc),
            "- State Change: {old_state} -> {new_state}".format(old_state=self.old_state, new_state=self.new_state),
            "- Reason for State Change: {reason}".format(reason=self.reason),
            "- Timestamp: {timestamp}".format(timestamp=self.timestamp),
            "- AWS Account: {account_id}".format(account_id=self.account_id),
            "- Alarm Arn: {alarm_arn}".format(alarm_arn=self.alarm_arn),
            "",
            "발생 시간: {year}년 {month}월 {day}일 {hour}시 {minute}분 {second}초".format(year=date[0], month=date[1], day=date[2], hour=time[0], minute=time[1], second=time[2])
        ]

        return content_lines


# Auto Scaling이 발생한 알람 이벤트를 정의한 클래스
class AutoscalingAlarm(AlarmEvent):
    # 생성자
    def __init__(self, event):
        # 부모 클래스 생성자 호출
        super().__init__(event)

        # message에서 데이터 추출
        self.detail_type = self.message.get('detail-type')
        self.account = self.message.get('account')
        self.start_time = self.message['detail'].get('StartTime') if self.message.get('detail') else None
        self.end_time = self.message['detail'].get('EndTime') if self.message.get('detail') else None
        self.target = self.message['detail'].get('AutoScalingGroupName') if self.message.get('detail') else None
        self.content = self.message.get('detail')

        # message에 없는 데이터 생성
        self.metric = 'autoscaling'
        self.priority = 'Medium'

        # 위에서 추출한 데이터를 이용하여 새로운 데이터 생성
        try:
            self.target_pattern = [p for p in globals()['METRIC_INFO'][self.metric] if re.compile(p).search(self.target)][0]
            self.jira_epic = globals()['METRIC_INFO'][self.metric][self.target_pattern]['jira_epic']
            self.slack_channel = globals()['METRIC_INFO'][self.metric][self.target_pattern]['slack_channel']
        except TypeError:
            self.target_pattern = None
            self.jira_epic = None
            self.slack_channel = None
        # Scale Out
        try:
            self.scale_out = re.compile('Launch Successful').findall(self.message['detail-type'])
        except KeyError:
            self.scale_out = None
        # Scale In
        try:
            self.scale_in = re.compile('Terminate Successful').findall(self.message['detail-type'])
        except KeyError:
            self.scale_in = None
        # Scale 상태 추출
        self.scale_status = 'OUT' if self.scale_out else 'IN' if self.scale_in else None
        # Auto Scaling 발생 전의 상태 추출
        try:
            self.old_status = re.compile('from \d+').findall(self.message['detail']['Cause'])[0].split(' ')[1] if re.compile('from \d+').findall(self.message['detail']['Cause']) else None
        except KeyError:
            self.old_status = None
        # Auto Scaling 발생 후의 상태 추출
        try:
            self.new_status = re.compile('to \d+').findall(self.message['detail']['Cause'])[0].split(' ')[1] if re.compile('to \d+').findall(self.message['detail']['Cause']) else None
        except KeyError:
            self.new_status = None
        # Auto Scaling 경과 시간 계산
        try:
            self.elased_time = ' '.join([''.join(words) for words in zip([s.strip('0') for s in str(datetime.datetime.strptime(self.end_time, '%Y-%m-%dT%H:%M:%S.%fZ') - datetime.datetime.strptime(self.start_time, '%Y-%m-%dT%H:%M:%S.%fZ')).split(':')], ['시간', '분', '초']) if words[0] != ''])
        except TypeError:
            self.elased_time = None

    # AWS S3에 업로드하는 함수
    def upload_s3(self, **kwargs):
        # S3에 업로드하기 위해 필요한 데이터 선언
        # message 원문 그대로 S3에 저장
        s3_data = str(self.message)
        s3_bucket = globals()['AWS_INFO']['s3']['bucket']
        dir_name = globals()['AWS_INFO']['account'][self.account] if self.account.isdigit() else self.account
        file_name = '{alarm_name}--{timestamp}'.format(alarm_name=self.metric, timestamp=self.timestamp)
        s3_path = '{dir_name}/{file_name}.txt'.format(dir_name=dir_name, file_name=file_name)

        # 부모 클래스의 메소드 호출
        super().upload_s3(s3_data, s3_bucket, s3_path)

        # S3에 저장된 CSV 파일 링크 생성
        s3_link = 'https://{s3_bucket}.s3.ap-northeast-2.amazonaws.com/{dir_name}/{file_name}.txt'.format(s3_bucket=s3_bucket, dir_name=dir_name, file_name=file_name)

        return s3_link

    # 알람이 발생한 resource name에서 env를 추출하는 함수
    def get_environment(self):
        # 두 키워드(Launch, Terminate)에 속하지 않으면 메세지 전송 안함
        return {} if not self.scale_status else {globals().get('ENVIRONMENT_INFO')[e]['env']: globals().get('ENVIRONMENT_INFO')[e]['word'] for e in globals().get('ENVIRONMENT_INFO') if re.compile(e).search(self.target.split('-')[3])} if self.target else None

    # 알람 메세지를 생성하는 함수
    def make_message(self, env):
        # UTC를 KST로 변환하는 함수 호출
        date, time = convert_kst(self.start_time)

        # 알람 메세지 포맷에 맞춰서 데이터 입력
        content_lines = [
            "[ {env} / {category} / {instance_type} Auto Scale 발생 ]".format(env=env[0], category='MSACompute', instance_type=self.target),
            "",
            "Auto Scaling Node: NGINX",
            "Auto Scaling IN/OUT: {scale_status}".format(scale_status=self.scale_status),
            "Auto Scaling 대상: {target}".format(target=self.target),
            "Auto Scaling Capacity: {old_status} -> {new_status}".format(old_status=self.old_status, new_status=self.new_status),
            "Auto Scaling 소요 시간: {elased_time}".format(elased_time=self.elased_time),
            "",
            "실행 내용:",
            "{content}".format(content=json.dumps(self.content).replace('{', '{\n\t').replace(', "', ',\n\t"').replace('},', '\t},').replace('}', '\n}')),
            "",
            "발생 시간: {year}년 {month}월 {day}일 {hour}시 {minute}분 {second}초".format(year=date[0], month=date[1], day=date[2], hour=time[0], minute=time[1], second=time[2])
        ]

        return content_lines


# RDS Failover가 발생한 알람 이벤트를 정의한 클래스
class RDSFailoverAlarm(AlarmEvent):
    # 생성자
    def __init__(self, event):
        # 부모 클래스 생성자 호출
        super().__init__(event)

        # message에서 데이터 추출
        self.event_time = 'T'.join(self.message['Event Time'].split('.')[0].split(' '))
        self.source_id = self.message['Source ID']

        # message에 없는 데이터 생성
        self.target = 'RDS'
        self.metric = 'DB Failover EVENT'
        self.priority = 'Medium'

        # 위에서 추출한 데이터를 이용하여 새로운 데이터 생성
        self.target_pattern = [p for p in globals()['METRIC_INFO'][self.metric] if re.compile(p).search(self.target)][0]
        self.category = globals()['METRIC_INFO'][self.metric][self.target_pattern]['jira_epic'].split(' ')[1]
        self.error_level = globals()['METRIC_INFO'][self.metric][self.target_pattern]['error_level']
        self.level_comment = globals()['LEVEL_INFO'].get(self.error_level)
        self.priority = 'High' if self.error_level in ['1급', '2급', '3급'] else 'Medium'
        self.error_effect = globals()['METRIC_INFO'][self.metric][self.target_pattern]['error_effect']
        self.jira_epic = globals()['METRIC_INFO'][self.metric][self.target_pattern]['jira_epic']
        self.slack_channel = globals()['METRIC_INFO'][self.metric][self.target_pattern]['slack_channel']

    # AWS S3에 업로드하는 함수
    def upload_s3(self, **kwargs):
        # S3에 업로드하기 위해 필요한 데이터 선언
        # message 원문 그대로 S3에 저장
        s3_data = str(self.message)
        s3_bucket = globals()['AWS_INFO']['s3']['bucket']
        dir_name = globals()['AWS_INFO']['account'][self.source_id.split('-')[1]] if self.source_id.split('-')[1].isdigit() else self.source_id.split('-')[1]
        file_name = '{alarm_name}--{timestamp}'.format(alarm_name=self.metric, timestamp=self.timestamp)
        s3_path = '{dir_name}/{file_name}.txt'.format(dir_name=dir_name, file_name=file_name)

        # 부모 클래스의 메소드 호출
        super().upload_s3(s3_data, s3_bucket, s3_path)

        # S3에 저장된 CSV 파일 링크 생성
        s3_link = 'https://{s3_bucket}.s3.ap-northeast-2.amazonaws.com/{dir_name}/{file_name}.txt'.format(s3_bucket=s3_bucket, dir_name=dir_name, file_name=file_name)

        return s3_link

    # 알람이 발생한 resource name에서 env를 추출하는 함수
    def get_environment(self):
        # source_id에서 환경 데이터 추출
        return {globals().get('ENVIRONMENT_INFO')[e]['env']: globals().get('ENVIRONMENT_INFO')[e]['word'] for e in globals().get('ENVIRONMENT_INFO') if re.compile(e).search(self.source_id.split('-')[3])}

    # 알람 메세지를 생성하는 함수
    def make_message(self, env):
        # UTC를 KST로 변환하는 함수 호출
        date, time = convert_kst(self.event_time)

        # 알람 메세지 포맷에 맞춰서 데이터 입력
        content_lines = [
            "[ {env} / {category} / {instance_type} / {resource} RDS FailOver 발생 ]".format(env=env[0], category=self.category, instance_type=globals()['AWS_INFO']['type'][self.source_id.split('-')[0]], resource=self.source_id),
            "장애 레벨: {error_level}({level_comment})".format(error_level=self.error_level, level_comment=self.level_comment),
            "장애 영향: {error_effect}".format(error_effect=self.error_effect),
            "장애 대상: {target}".format(target=self.source_id),
            "장애 메트릭: {metric}".format(metric=self.metric),
            "장애 내용:",
            "{content}".format(content=json.dumps(self.message).replace('{', '{\n\t').replace(', "', ',\n\t"').replace('},', '\t},').replace('}', '\n}')),
            "",
            "발생 시간: {year}년 {month}월 {day}일 {hour}시 {minute}분 {second}초".format(year=date[0], month=date[1], day=date[2], hour=time[0], minute=time[1], second=time[2])
        ]

        return content_lines


# Deep Security가 발생한 알람 이벤트를 정의한 클래스
class DeepSecurityAlarm(AlarmEvent):
    # 생성자
    def __init__(self, event):
        # 부모 클래스 생성자 호출
        super().__init__(event)

        # 초기값
        self.threat_level = 'Low'
        self.severity_string = ''

        # Intrusion Prevention event
        if self.message[0].get('Action'):
            # 이벤트 구분하기 위한 flag 정의
            self.flag = 0

        # System event
        elif self.message[0].get('ActionBy'):
            # 이벤트 구분하기 위한 flag 정의
            self.flag = 1

            # message에서 데이터 추출
            self.description = self.message[0]['Description']
            self.event_type = self.message[0]['EventType']
            self.severity = self.message[0]['Severity']
            self.severity_string = self.message[0]['SeverityString']
            self.origin_string = self.message[0]['OriginString']
            self.target_name = self.message[0]['TargetName']
            self.target_type = self.message[0]['TargetType']
            self.title = self.message[0]['Title']

            # 위에서 추출한 데이터를 이용하여 새로운 데이터 생성
            self.threat_level = 'Critical' if self.severity == 100 else 'High' if self.severity >= 50 else 'Medium' if self.severity >= 25 else 'Low'

        # message에서 데이터 추출
        self.log_date = self.message[0]['LogDate']

        # message에 없는 데이터 생성
        self.metric = 'deep_security'
        self.target = 'ds'
        self.instance_type = 'Deep Security'

        # 위에서 추출한 데이터를 이용하여 새로운 데이터 생성
        self.priority = 'High' if self.threat_level in ['Critical', 'High'] else 'Medium'
        self.target_pattern = [p for p in globals()['METRIC_INFO'][self.metric] if re.compile(p).search(self.target)][0]
        self.category = globals()['METRIC_INFO'][self.metric][self.target_pattern]['jira_epic'].split(' ')[1]
        self.service_effect = globals()['METRIC_INFO'][self.metric][self.target_pattern]['error_effect']
        self.jira_epic = globals()['METRIC_INFO'][self.metric][self.target_pattern]['jira_epic']
        self.slack_channel = globals()['METRIC_INFO'][self.metric][self.target_pattern]['slack_channel']

    # AWS S3에 업로드하는 함수
    def upload_s3(self, **kwargs):
        # S3에 업로드하기 위해 필요한 데이터 선언
        # message 원문 그대로 S3에 저장
        s3_data = str(self.message)
        s3_bucket = globals()['AWS_INFO']['s3']['bucket']
        dir_name = globals()['AWS_INFO']['account'][self.topic_arn.split(':')[-1].split('-')[1]] if self.topic_arn.split(':')[-1].split('-')[1].isdigit() else self.topic_arn.split(':')[-1].split('-')[1]
        file_name = '{alarm_name}--{timestamp}'.format(alarm_name=self.metric, timestamp=self.timestamp)
        s3_path = '{dir_name}/{file_name}.txt'.format(dir_name=dir_name, file_name=file_name)

        # 부모 클래스의 메소드 호출
        super().upload_s3(s3_data, s3_bucket, s3_path)

        # S3에 저장된 CSV 파일 링크 생성
        s3_link = 'https://{s3_bucket}.s3.ap-northeast-2.amazonaws.com/{dir_name}/{file_name}.txt'.format(s3_bucket=s3_bucket, dir_name=dir_name, file_name=file_name)

        return s3_link

    # 알람이 발생한 resource name에서 env를 추출하는 함수
    def get_environment(self):
        # 두 키워드(Info, Warning)에 속하면 메세지 전송 안함
        return {} if self.severity_string in ['', 'Info', 'Warning'] or self.origin_string in ['Manager'] else {globals().get('ENVIRONMENT_INFO')[e]['env']: globals().get('ENVIRONMENT_INFO')[e]['word'] for e in globals().get('ENVIRONMENT_INFO') if re.compile(e).search(self.topic_arn.split('-')[-1].strip())}

    # 알람 메세지를 생성하는 함수
    def make_message(self, env):
        # 초기값
        content_lines = None

        # Intrusion Prevention event
        if self.flag == 0:
            # UTC를 KST로 변환하는 함수 호출
            date, time = convert_kst(self.log_date)

            # 알람 메세지 포맷에 맞춰서 데이터 입력
            content_lines = [
                "[ {env} / {category} / {instance_type} 보안 탐지 ]".format(env=env[0], category=self.category, instance_type=self.instance_type),
                "",
                "보안 레벨: {threat_level}".format(threat_level=self.threat_level),
                "서비스 영향: {service_effect}".format(service_effect=self.service_effect),
                "",
                "보안 내용:",
                "- Content: {content}".format(content=json.dumps(self.message[0]).replace('{', '{\n\t').replace(', "', ',\n\t"').replace('},', '\t},').replace('}', '\n}')),
                "",
                "발생 시간: {year}년 {month}월 {day}일 {hour}시 {minute}분 {second}초".format(year=date[0], month=date[1], day=date[2], hour=time[0], minute=time[1], second=time[2])
            ]

        # System event
        elif self.flag == 1:
            # UTC를 KST로 변환하는 함수 호출
            date, time = convert_kst(self.log_date)

            # 알람 메세지 포맷에 맞춰서 데이터 입력
            content_lines = [
                "[ {env} / {category} / {instance_type} 보안 탐지 ]".format(env=env[0], category=self.category, instance_type=self.instance_type),
                "",
                "보안 레벨: {threat_level}".format(threat_level=self.threat_level),
                "서비스 영향: {service_effect}".format(service_effect=self.service_effect),
                "보안 대상: {target_name}[{target_type}]".format(target_name=self.target_name, target_type=self.target_type),
                "보안 탐지: {event_type}".format(event_type=self.event_type),
                "",
                "보안 내용:",
                "- Title: {title}".format(title=self.title),
                "- Description: {description}".format(description=self.description),
                "",
                "발생 시간: {year}년 {month}월 {day}일 {hour}시 {minute}분 {second}초".format(year=date[0], month=date[1], day=date[2], hour=time[0], minute=time[1], second=time[2])
            ]

        return content_lines


# JIRA issue를 생성하기 위한 함수
def make_issue(title, jira_content, jira_epic, priority, jira_participants, timestamp):
    # JIRA issue를 생성하기 위해 필요한 데이터 추출
    jira = JIRA(options={'server': globals()['JIRA_INFO']['url']}, basic_auth=(globals()['JIRA_INFO']['email'], globals().get('DECRYPTED_JIRATOKEN')))
    parent = globals()['JIRA_INFO']['epic'][jira_epic]['parent']
    project = parent.split('-')[0]
    assignee = globals()['JIRA_INFO']['receiver'][globals()['JIRA_INFO']['epic'][jira_epic]['assignee']]
    custom_field = globals()['JIRA_INFO']['project'][project]['custom_field']
    key = globals()['JIRA_INFO']['project'][project]['key']

    # JIRA issue 생성
    issue_id = jira.create_issue(fields={
        'project': {'key': project},
        'parent': {'key': parent},
        'issuetype': {'name': '작업'},
        'summary': title,
        'description': jira_content,
        'priority': {'name': priority},
        'duedate': timestamp.split('T')[0],
        'assignee': {'id': assignee},
        custom_field['participants']: [{'id': globals()['JIRA_INFO']['receiver'][name]} for name in jira_participants],
        custom_field['start_date']: timestamp.split('T')[0],
        'labels': []
    })

    # JIRA issue 생성 정보를 전달하기 위한 dict 생성
    jira_dict = {
        'url': globals()['JIRA_INFO']['url'],
        'project': project,
        'key': key,
        'issue_id': issue_id
    }

    return jira_dict


# Slack channel에 메세지를 보내기 위한 함수
def send_message(content, receiver, slack_channel):
    # Slack 수신자를 추가하는 코드
    slack_receiver = ' '.join([globals()['SLACK_INFO']['receiver'][name] for name in receiver])
    slack_content = "{slack_receiver}\n\n{content}".format(slack_receiver=slack_receiver, content=content)

    # Slack Webhook Url 추출
    webhook_url = globals()['SLACK_INFO']['channel'][slack_channel]['url']

    # Slack channel에 보낼 메세지 생성
    message = {
        'channel': slack_channel,
        'text': slack_content
    }

    # Slack channel에 메세지 전송
    req = request.Request(webhook_url, json.dumps(message).encode('utf-8'))
    try:
        response = request.urlopen(req)
        response.read()
        LOGGER.info('Message posted to {}'.format(message['channel']))

    except error.HTTPError as e:
        LOGGER.error('Request failed: {} {}'.format(e.code, e.reason))

    except error.URLError as e:
        LOGGER.error('Server connection failed: {}'.format(e.reason))


# Lambda가 실행하는 함수
def lambda_handler(event, _context):
    # event를 로그로 남기는 코드
    LOGGER.info("Event: {}".format(str(event)))

    # 객체 생성
    alarm_event = AlarmEvent(event)

    # 메세지 타입에 따라 알람 구분
    # 메세지 타입이 dictionary인 경우
    if str(type(alarm_event.message)) == "<class 'dict'>":
        # CloudWatch
        if alarm_event.message.get('AlarmName'):
            alarm_event = CloudwatchAlarm(event)

        # Auto Scaling
        elif alarm_event.message.get('source') == 'aws.autoscaling':
            alarm_event = AutoscalingAlarm(event)

        # RDS Failover
        elif alarm_event.message.get('Event Source'):
            alarm_event = RDSFailoverAlarm(event)

    # 메세지 타입이 list인 경우
    # Deep Security
    elif str(type(alarm_event.message)) == "<class 'list'>":
        alarm_event = DeepSecurityAlarm(event)

    # S3에 업로드
    s3_link = None
    try:
        s3_link = alarm_event.upload_s3()
    except Exception as e:
        print("This alarm does NOT save the data to S3")
        LOGGER.info(e)

    # 알람이 발생한 resource name에 env 정보가 없다면 메세지 전송 안함
    if not alarm_event.get_environment():
        print('This alarm is NOT sent')
        return {"statusCode": 200}

    # 추출된 환경별로 아래 코드 실행
    for env in alarm_event.get_environment().items():
        content_lines = alarm_event.make_message(env)

        # S3 링크를 메세지 내용에 추가하는 코드
        if s3_link:
            content_lines += [
                "",
                "[S3 Link]",
                "Link: {}".format(s3_link)
            ]

        content = '\n\n'.join(content_lines)
        title = content_lines[0]

        # 대시보드 링크를 메세지 내용에 추가하는 코드
        link_info = [
            "",
            "[Kibana Dashboard]",
            "Link: {}".format(globals()['DASHBOARD_INFO']['kibana'].get(env[0])),
            "",
            "[Cloudwatch Dashboard]",
            "Link: {}".format(globals()['DASHBOARD_INFO']['cloudwatch'].get(env[0])),
            "",
            "[Grafana Dashboard]",
            "Link: {}".format(globals()['DASHBOARD_INFO']['grafana'].get(env[0]))
        ]
        content_with_dashboard = "{content}\n\n{link_info}".format(content=content, link_info='\n\n'.join(link_info))

        try:
            # JIRA issue를 생성하는 코드
            jira_epic = ' '.join([env[0], alarm_event.jira_epic])
            jira_participants = globals()['JIRA_INFO']['epic'][jira_epic]['participants'] if jira_epic.split(' ')[-1] != 'Application' else globals()['JIRA_INFO']['epic'][jira_epic]['participants'] + [globals()['DEVELOP_PART_INFO'][keyword] for keyword in globals().get('DEVELOP_PART_INFO') if re.compile('-{}-'.format(keyword)).search(alarm_event.target)]
            jira_dict = make_issue(title, content_with_dashboard, jira_epic, alarm_event.priority, jira_participants, alarm_event.timestamp)

            # JIRA issue 관련 정보를 메세지 내용에 추가하는 코드
            issue_info = [
                "",
                "[Jira Board]",
                "{url}/jira/software/projects/{project}/boards/{key}?selectedIssue={id}".format(url=jira_dict['url'], project=jira_dict['project'], key=jira_dict['key'], id=jira_dict['issue_id']),
                "",
                "[Jira Issue]",
                "Epic: {jira_epic}".format(jira_epic=alarm_event.jira_epic),
                "ID: {issue_id}\n{url}/browse/{issue_id}".format(url=jira_dict['url'], issue_id=jira_dict['issue_id'])
            ]
            content = "{content}\n\n{issue_info}\n\n{link_info}".format(content=content, issue_info='\n\n'.join(issue_info), link_info='\n\n'.join(link_info))

        except Exception as e:
            content = content_with_dashboard
            print("Jira is NOT working")
            LOGGER.info(e)

        try:
            # 채널에 Slack 메세지를 전송하는 코드
            slack_channel = '-'.join([env[1], alarm_event.slack_channel])
            slack_receiver = globals()['SLACK_INFO']['channel'][slack_channel]['receiver'] if slack_channel.split('-')[-2] != '서비스' else globals()['SLACK_INFO']['channel'][slack_channel]['receiver'] + [globals()['DEVELOP_PART_INFO'][keyword] for keyword in globals().get('DEVELOP_PART_INFO') if re.compile('-{}-'.format(keyword)).search(alarm_event.target)]
            send_message(content, slack_receiver, slack_channel)

        except Exception as e:
            print("Slack is NOT working")
            LOGGER.info(e)
