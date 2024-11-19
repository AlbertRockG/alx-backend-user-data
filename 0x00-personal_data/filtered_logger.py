#!/usr/bin/env python3
"""Module for redacting sensitive user data from logs."""

import re
import logging
from typing import List
import mysql.connector
from os import getenv

PII_FIELDS = ('name', 'email', 'phone', 'ssn', 'password')


class RedactingFormatter(logging.Formatter):
    """
    Formatter class that redacts specified fields in log messages.

    Attributes:
        REDACTION (str): The string used to redact sensitive information.
        FORMAT (str): The format string for log messages.
        SEPARATOR (str): The separator used between log fields.
    """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        """
        Initialize the RedactingFormatter with specified fields.

        Args:
            fields (List[str]): List of field names to redact in log messages.
        """
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """
        Format the log record, redacting sensitive fields.

        Args:
            record (logging.LogRecord): The log record to format.

        Returns:
            str: The formatted and redacted log message.
        """
        formatted_message = super().format(record)
        redacted_message = filter_datum(
            self.fields,
            self.REDACTION,
            formatted_message,
            self.SEPARATOR
        )
        return redacted_message


def filter_datum(
        fields: List[str], redaction: str, message: str, separator: str
        ) -> str:
    """
    Redact specified fields in a log message.

    Args:
        fields (List[str]): List of field names to redact.
        redaction (str): The string to replace sensitive data with.
        message (str): The original log message.
        separator (str): The separator used between fields in the message.

    Returns:
        str: The log message with specified fields redacted.
    """
    for field in fields:
        pattern = f"{field}=.*?{separator}"
        replacement = f"{field}={redaction}{separator}"
        message = re.sub(pattern, replacement, message)
    return message


def get_logger() -> logging.Logger:
    """
    Configure and return a logger with a redacting formatter.

    Returns:
        logging.Logger: Configured logger instance.
    """
    logger = logging.getLogger("user_data")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    handler = logging.StreamHandler()
    handler.setFormatter(RedactingFormatter(PII_FIELDS))
    logger.addHandler(handler)
    return logger


def get_db() -> mysql.connector.connection.MySQLConnection:
    """
    Establish and return a connection to the MySQL database.

    Environment Variables:
        PERSONAL_DATA_DB_USERNAME (str): Database username. Defaults to 'root'.
        PERSONAL_DATA_DB_PASSWORD (str): Database password. Defaults to ''.
        PERSONAL_DATA_DB_HOST (str): Database host. Defaults to 'localhost'.
        PERSONAL_DATA_DB_NAME (str): Database name.

    Returns:
        mysql.connector.connection.MySQLConnection: Database connection object.
    """

    username = getenv('PERSONAL_DATA_DB_USERNAME', 'root')
    password = getenv('PERSONAL_DATA_DB_PASSWORD', '')
    host = getenv('PERSONAL_DATA_DB_HOST', 'localhost')
    db_name = getenv('PERSONAL_DATA_DB_NAME')

    db = msql.connector.connection.MySQLConnection(
        user=username,
        password=password,
        host=host,
        database=db_name
    )
    return db


def main():
    """
    Main function to retrieve user data from the database and log it.

    Connects to the database, fetches all user records, formats each record,
    and logs the redacted information.
    """
    logger = get_logger()
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users;")

    result = cursor.fetchall()
    for data in result:
        message = (
            f"name={data[0]}; "
            f"email={data[1]}; "
            f"phone={data[2]}; "
            f"ssn={data[3]}; "
            f"password={data[4]}; "
            f"ip={data[5]}; "
            f"last_login={data[6]}; "
            f"user_agent={data[7]};"
        )
        print(message)
        logger.info(message)

    cursor.close()
    db.close()


if __name__ == '__main__':
    main()
