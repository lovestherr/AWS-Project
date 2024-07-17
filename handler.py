import json
import boto3
from boto3.dynamodb.conditions import Key
from botocore.exceptions import NoCredentialsError, ClientError
import base64

dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table('Course')
parents_table = dynamodb.Table('parents')
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
    student_ids = body['StudentIDs']
    teacher_id = body['TeacherID']
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
    table.put_item(
        Item={
            'CourseID': course_id,
            'CourseName': course_name,
            'CourseDescription': course_description,
            'ContentPath': content_path,
        }
    )

    # Add course id to students' enrolled courses
    for student_id in student_ids:
            add_course_to_student(student_id, course_id)
    

    add_course_to_teacher(teacher_id, course_id)
    
    return {
        'statusCode': 200,
        'headers': {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': 'true'
        },
        'body': json.dumps('Course created and added to student successfully')
    }

def upload_file(file_content, bucket_name, object_name, region_name='eu-west-1'):
    try:
        s3.put_object(Bucket=bucket_name, Key=object_name, Body=file_content)
    except NoCredentialsError:
        return False, "Credentials not available"
    except ClientError as e:
        return False, str(e)
    return True, "File uploaded successfully"

def add_course_to_student(student_id, course_id):
    table = dynamodb.Table('students')
    
    # Update the student's enrolled courses list
    response = table.update_item(
        Key={'studentID': student_id},
        UpdateExpression="SET enrolledCourses = list_append(if_not_exists(enrolledCourses, :empty_list), :course)",
        ExpressionAttributeValues={
            ':course': [course_id],
            ':empty_list': []
        },
        ReturnValues="UPDATED_NEW"
    )

def add_course_to_teacher(teacher_id, course_id):
    table = dynamodb.Table('teachers')
    
    # Update the student's enrolled courses list
    response = table.update_item(
        Key={'teacherID': teacher_id},
        UpdateExpression="SET enrolledCourses = list_append(if_not_exists(enrolledCourses, :empty_list), :course)",
        ExpressionAttributeValues={
            ':course': [course_id],
            ':empty_list': []
        },
        ReturnValues="UPDATED_NEW"
    )

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

def list_students(event, context):
    table = dynamodb.Table('students')
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

def delete_course(event, context):
    # Parse the input
    body = json.loads(event['body'])
    
    course_id = body['CourseID']
    
    # Get the course details to find the file path
    response = table.get_item(Key={'CourseID': course_id})
    item = response.get('Item')
    if not item:
        return {
            'statusCode': 404,
            'headers': {
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Credentials': 'true'
            },
            'body': json.dumps({'error': 'Course not found'})
        }

    # Define S3 object name
    object_name = f'uploads/{course_id}/{item["CourseName"]}.txt'

    # Delete file from S3
    success, message = delete_file(bucket_name, object_name)
    if not success:
        return {
            'statusCode': 500,
            'headers': {
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Credentials': 'true'
            },
            'body': json.dumps(f"Failed to delete file: {message}")
        }

    # Delete the item from DynamoDB
    table.delete_item(Key={'CourseID': course_id})
    
    return {
        'statusCode': 200,
        'headers': {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': 'true'
        },
        'body': json.dumps('Course deleted successfully')
    }

def delete_file(bucket_name, object_name):
    try:
        s3.delete_object(Bucket=bucket_name, Key=object_name)
    except NoCredentialsError:
        return False, "Credentials not available"
    except ClientError as e:
        return False, str(e)
    return True, "File deleted successfully"

def edit_course(event, context):
    # Parse the input
    body = json.loads(event['body'])
    
    course_id = body['CourseID']
    updated_fields = {key: value for key, value in body.items() if key not in ['CourseID', 'FileContent']}

    # Update file content if provided
    if 'FileContent' in body:
        file_content_base64 = body['FileContent']
        file_content = base64.b64decode(file_content_base64)

        # Get current course details to determine S3 object path
        response = table.get_item(Key={'CourseID': course_id})
        item = response.get('Item')
        if not item:
            return {
                'statusCode': 404,
                'headers': {
                    'Access-Control-Allow-Origin': '*',
                    'Access-Control-Allow-Credentials': 'true'
                },
                'body': json.dumps({'error': 'Course not found'})
            }

        object_name = f'uploads/{course_id}/{item["CourseName"]}.txt'
        
        # Upload updated file to S3
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

    # Update the item in DynamoDB
    update_expression = 'SET ' + ', '.join(f"{key} = :{key}" for key in updated_fields.keys())
    expression_attribute_values = {f":{key}": value for key, value in updated_fields.items()}

    table.update_item(
        Key={'CourseID': course_id},
        UpdateExpression=update_expression,
        ExpressionAttributeValues=expression_attribute_values
    )
    
    return {
        'statusCode': 200,
        'headers': {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': 'true'
        },
        'body': json.dumps('Course updated successfully')
    }

def add_student_to_parent(event, context):
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
    
    parent_id = body['ParentID']
    student_id = body['StudentID']

    try:
        # Update the parent's studentID list
        response = parents_table.update_item(
            Key={'parentID': parent_id},
            UpdateExpression="SET studentID = list_append(if_not_exists(studentID, :empty_list), :student)",
            ExpressionAttributeValues={
                ':student': [student_id],
                ':empty_list': []
            },
            ReturnValues="UPDATED_NEW"
        )
        
        return {
            'statusCode': 200,
            'headers': {
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Credentials': 'true'
            },
            'body': json.dumps('Student added to parent successfully')
        }
    except NoCredentialsError:
        return {
            'statusCode': 500,
            'headers': {
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Credentials': 'true'
            },
            'body': json.dumps('Credentials not available')
        }
    except ClientError as e:
        return {
            'statusCode': 500,
            'headers': {
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Credentials': 'true'
            },
            'body': json.dumps(f"Failed to update parent: {str(e)}")
        }

def add_file_to_student_reports(event, context):
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
    
    student_id = body['StudentID']
    content_path = body['ContentPath']
    file_content_base64 = body['FileContent']
    
    # Decode the base64 file content
    file_content = base64.b64decode(file_content_base64)
    
    # Define S3 object name
    object_name = f'reports/{student_id}/{content_path}'
    
    # Upload the file to S3
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
    
    return {
        'statusCode': 200,
        'headers': {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': 'true'
        },
        'body': json.dumps('File uploaded successfully')
    }

def get_studentEnrolledCourses(event, context):
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
    
def get_teacherEnrolledCourses(event, context):
    table = dynamodb.Table('teachers')
    teacher_id = event['queryStringParameters']['teacherID']
    result = table.get_item(Key={'teacherID': teacher_id})
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