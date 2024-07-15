import json
import boto3
from boto3.dynamodb.conditions import Key
from botocore.exceptions import NoCredentialsError, ClientError
import base64

dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table('Course')

s3 = boto3.client('s3')
client = boto3.client('cognito-idp')

# AWS S3 Bucket name
bucket_name = 'yyeproject'

def create(event, context):
    if event['httpMethod'] == 'OPTIONS':
        return {
            'statusCode': 200,
            'headers': {
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Methods': 'OPTIONS,POST',
                'Access-Control-Allow-Headers': 'Content-Type'
            },
            'body': ''
        }

    # Parse the input
    body = json.loads(event['body'])
    
    course_id = body['CourseID']
    course_name = body['CourseName']
    course_description = body['CourseDescription']
    content_path = body['ContentPath']

    # Get file content and decode it from base64
    file_content_base64 = body['FileContent']
    file_content = base64.b64decode(file_content_base64)
    
    # Define S3 bucket and object name
    object_name = f'uploads/{course_id}/{course_name}.txt'
    
    # Upload file to S3
    success, message = upload_file(file_content, bucket_name, object_name)
    
    if not success:
        return {
            'statusCode': 500,
            'headers': {
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Credentials': 'true'
            },
            'body': json.dumps(f"Failed to upload file: {message}")
        }
    
    # Put the item into DynamoDB
    response = table.put_item(
        Item={
            'CourseID': course_id,
            'CourseName': course_name,
            'CourseDescription': course_description,
            'ContentPath': content_path,
        }
    )
    
    return {
        'statusCode': 200,
        'headers': {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': 'true'
        },
        'body': json.dumps('Course created successfully')
    }

def upload_file(file_content, bucket_name, object_name, region_name='eu-west-1'):
    try:
        s3.put_object(Bucket=bucket_name, Key=object_name, Body=file_content)
    except NoCredentialsError:
        return False, "Credentials not available"
    except ClientError as e:
        return False, str(e)
    return True, "File uploaded successfully"

def get_item(event, context):
    table = dynamodb.Table('Course')
    course_id = event['queryStringParameters']['CourseID']
    result = table.get_item(Key={'CourseID': course_id})
    item = result.get('Item')
    if item:
        return {
            'statusCode': 200,
            'headers': {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': 'true'
        },
            'body': json.dumps(item)
        }
    else:
        return {
            'statusCode': 404,
            'headers': {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': 'true'
        },
            'body': json.dumps({'error': 'Item not found'})
        }

def list_items(event, context):
    table = dynamodb.Table('Course')
    result = table.scan()
    items = result.get('Items', [])
    return {
        'statusCode': 200,
        'headers': {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': 'true'
        },
        'body': json.dumps(items)
    }

def login(event, context):
    # Parse the body from the event
    body = json.loads(event['body'])
    username = body['email']
    password = body['password']
    
    try:
        response = client.initiate_auth(
            ClientId="4p6rtblq17qu1gotnkn4n96mlp",
            AuthFlow='USER_PASSWORD_AUTH',
            AuthParameters={
                'USERNAME': username,
                'PASSWORD': password
            }
        )
        return {
            'statusCode': 200,
            'headers': {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': 'true'
        },
            'body': json.dumps(response)
        }
    except client.exceptions.NotAuthorizedException as e:
        return {
            'statusCode': 401,
            'headers': {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': 'true'
        },
            'body': json.dumps({'error': 'Incorrect username or password {}, {}, {}'.format(username, password, e)})
        }
    except client.exceptions.UserNotFoundException:
        return {
            'statusCode': 404,
            'headers': {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': 'true'
        },
            'body': json.dumps({'error': 'User does not exist'})
        }
    except Exception as e:
        return {
            'statusCode': 500,
            'headers': {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': 'true'
        },
            'body': json.dumps({'error': str(e)})
        }

def get_enrolledCourses(event, context):
    table = dynamodb.Table('students')
    student_id = event['queryStringParameters']['studentID']
    result = table.get_item(Key={'studentID': student_id})
    item = result.get('Item')
    if item:
        return {
            'statusCode': 200,
            'headers': {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': 'true'
        },
            'body': json.dumps(item)
        }
    else:
        return {
            'statusCode': 404,
            'headers': {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': 'true'
        },
            'body': json.dumps({'error': 'Item not found'})
        }
    
def get_user_details(event, context):
    access_token = event['queryStringParameters']['access_token']
    try:
        # Call get_user method with the provided access token
        response = client.get_user(
            AccessToken=access_token
        )

        # Extract and return user details
        user_details = response['UserAttributes']
        return {
            'statusCode': 200,
            'headers': {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': 'true'
        },
            'body': json.dumps(user_details)
        }

    except client.exceptions.NotAuthorizedException as e:
        print("The access token is not valid.")
        return None
    except client.exceptions.UserNotFoundException as e:
        print("The user was not found.")
        return None
    except Exception as e:
        print(f"An error occurred: {e}")
        return None
