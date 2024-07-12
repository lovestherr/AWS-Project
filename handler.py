import json
import boto3
from boto3.dynamodb.conditions import Key

dynamodb = boto3.resource('dynamodb')
client = boto3.client('cognito-idp')

def create(event, context):
    table = dynamodb.Table('Course')
    # Parse the input
    body = json.loads(event['body'])
    
    course_id = body['CourseID']
    course_name = body['CourseName']
    course_description = body['CourseDescription']
    content_path = body['ContentPath']
    teacher_id = body['TeacherID']
    student_id = body['StudentID']
    
    # Put the item into DynamoDB
    response = table.put_item(
        Item={
            'CourseID': course_id,
            'CourseName': course_name,
            'CourseDescription': course_description,
            'ContentPath': content_path,
            'TeacherID': teacher_id,
            'StudentID': student_id
        }
    )
    
    return {
        'statusCode': 200,
        'body': json.dumps('Course created successfully')
    }

def get_item(event, context):
    table = dynamodb.Table('Course')
    course_id = event['queryStringParameters']['CourseID']
    result = table.get_item(Key={'CourseID': course_id})
    item = result.get('Item')
    if item:
        return {
            'statusCode': 200,
            'body': json.dumps(item)
        }
    else:
        return {
            'statusCode': 404,
            'body': json.dumps({'error': 'Item not found'})
        }

def list_items(event, context):
    table = dynamodb.Table('Course')
    result = table.scan()
    items = result.get('Items', [])
    return {
        'statusCode': 200,
        'body': json.dumps(items)
    }

def delete_item(event, context):
    table = dynamodb.Table('Course')
    course_id = event['queryStringParameters']['CourseID']
    table.delete_item(Key={'CourseID': course_id})
    return {
        'statusCode': 200,
        'body': json.dumps({'message': f'Deleted item {course_id}'})
    }

def update(event, context):
    table = dynamodb.Table('Course')
    course_id = event['queryStringParameters']['CourseID']
    body = json.loads(event['body'])
    
    update_expression = "SET "
    expression_attribute_values = {}
    for key, value in body.items():
        update_expression += f"{key} = :{key}, "
        expression_attribute_values[f":{key}"] = value

    # Remove trailing comma and space
    update_expression = update_expression.rstrip(", ")

    response = table.update_item(
        Key={'CourseID': course_id},
        UpdateExpression=update_expression,
        ExpressionAttributeValues=expression_attribute_values,
        ReturnValues="UPDATED_NEW"
    )

    return {
        'statusCode': 200,
        'body': json.dumps({'message': 'Item updated successfully', 'updatedAttributes': response.get('Attributes')})
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
            'body': json.dumps(response)
        }
    except client.exceptions.NotAuthorizedException as e:
        return {
            'statusCode': 401,
            'body': json.dumps({'error': 'Incorrect username or password {}, {}, {}'.format(username, password, e)})
        }
    except client.exceptions.UserNotFoundException:
        return {
            'statusCode': 404,
            'body': json.dumps({'error': 'User does not exist'})
        }
    except Exception as e:
        return {
            'statusCode': 500,
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
            'body': json.dumps(item)
        }
    else:
        return {
            'statusCode': 404,
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