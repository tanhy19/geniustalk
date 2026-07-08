import unittest
from unittest.mock import patch

from utils import db_logger


class SecurityAnswerResetTests(unittest.TestCase):
    @patch('utils.db_logger.set_document')
    @patch('utils.db_logger.get_document')
    def test_submit_security_answer_reset_request_creates_pending_doc(
        self,
        mock_get_document,
        mock_set_document,
    ):
        mock_get_document.return_value = None

        result = db_logger.submit_security_answer_reset_request(
            'User@Example.com',
            requested_by='user',
            message='forgot my answer',
        )

        self.assertTrue(result['success'])
        self.assertEqual(result['status'], 'pending')
        self.assertEqual(result['email'], 'user@example.com')
        mock_set_document.assert_called_once()
        self.assertEqual(mock_set_document.call_args.args[0], 'security_answer_reset_requests')
        payload = mock_set_document.call_args.args[2]
        self.assertEqual(payload['email'], 'user@example.com')
        self.assertEqual(payload['status'], 'pending')

    @patch('utils.db_logger.set_document')
    @patch('utils.db_logger.get_document')
    def test_approve_security_answer_reset_request_marks_approved(
        self,
        mock_get_document,
        mock_set_document,
    ):
        mock_get_document.return_value = {
            'email': 'user@example.com',
            'status': 'pending',
        }

        result = db_logger.approve_security_answer_reset_request(
            'user@example.com',
            approved_by='admin@example.com',
        )

        self.assertTrue(result['success'])
        self.assertEqual(result['status'], 'approved')
        mock_set_document.assert_called_once()
        payload = mock_set_document.call_args.args[2]
        self.assertEqual(payload['status'], 'approved')
        self.assertEqual(payload['approved_by'], 'admin@example.com')


if __name__ == '__main__':
    unittest.main()
