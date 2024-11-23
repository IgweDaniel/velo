# custom_exception_handler.py
from rest_framework.views import exception_handler
from rest_framework.exceptions import ValidationError
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from rest_framework.response import Response
from rest_framework import status


def custom_exception_handler(exc, context):
    # Call REST framework's default exception handler first,
    # to get the standard error response.
    response = exception_handler(exc, context)

    # Handle validation errors
    if isinstance(exc, ValidationError):
        custom_response_data = {"error": {}}
        for field, value in response.data.items():
            if isinstance(value, list) and len(value) == 1:
                custom_response_data["error"][field] = value[0]
            else:
                custom_response_data["error"][field] = value
        return Response(custom_response_data, status=response.status_code)

    # Handle invalid token errors
    if isinstance(exc, (InvalidToken, TokenError)):
        return Response(
            {"error": "Token is invalid or expired"},
            status=status.HTTP_401_UNAUTHORIZED,
        )

    # Handle other errors with a detail field
    if response is not None and "detail" in response.data:
        custom_response_data = {"error": response.data["detail"]}
        return Response(custom_response_data, status=response.status_code)

    return response
