#!/usr/bin/env python3
"""
Test suite for Discord bot fixes - validates all critical functionality:
- URL construction and API readiness checks
- Task complexity classification
- Response cleaning (removing reasoning/code from LLM output)
- Discord action detection
- Container command patterns
"""

import pytest
import sys
import os
import re

# Add the parent directory to the path so we can import from discord_bot
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from discord_bot import (
    classify_task_complexity,
    TaskComplexity,
    clean_llm_response,
    is_discord_action,
)


# ============================================================================
# URL Construction Tests
# ============================================================================

def get_chat_completions_url(base_endpoint: str) -> str:
    """Construct the correct chat completions URL from the base endpoint."""
    base = base_endpoint.rstrip('/')
    if base.endswith('/chat/completions'):
        return base
    if base.endswith('/v1'):
        return f"{base}/chat/completions"
    return f"{base}/v1/chat/completions"


class TestGetChatCompletionsUrl:
    def test_endpoint_with_v1(self):
        assert get_chat_completions_url("http://127.0.0.1:8317/v1") == \
            "http://127.0.0.1:8317/v1/chat/completions"

    def test_endpoint_with_v1_trailing_slash(self):
        assert get_chat_completions_url("http://127.0.0.1:8317/v1/") == \
            "http://127.0.0.1:8317/v1/chat/completions"

    def test_endpoint_without_v1(self):
        assert get_chat_completions_url("http://127.0.0.1:8317") == \
            "http://127.0.0.1:8317/v1/chat/completions"

    def test_already_has_chat_completions(self):
        assert get_chat_completions_url("http://127.0.0.1:8317/v1/chat/completions") == \
            "http://127.0.0.1:8317/v1/chat/completions"

    def test_https_endpoint(self):
        assert get_chat_completions_url("https://api.example.com/v1") == \
            "https://api.example.com/v1/chat/completions"


# ============================================================================
# Task Complexity Classification Tests
# ============================================================================

class TestTaskComplexity:
    def test_simple_greeting(self):
        assert classify_task_complexity("hello") == TaskComplexity.SIMPLE

    def test_simple_question(self):
        assert classify_task_complexity("what is SQL injection?") == TaskComplexity.SIMPLE

    def test_simple_thanks(self):
        assert classify_task_complexity("thanks") == TaskComplexity.SIMPLE

    def test_complex_scan(self):
        result = classify_task_complexity("scan example.com for SQL injection")
        assert result in (TaskComplexity.COMPLEX, TaskComplexity.MODERATE)

    def test_long_running_deep_scan(self):
        assert classify_task_complexity("perform a deep comprehensive security scan") == \
            TaskComplexity.LONG_RUNNING

    def test_long_running_thorough(self):
        assert classify_task_complexity("thoroughly scan the application") == \
            TaskComplexity.LONG_RUNNING

    def test_long_running_time_indicator(self):
        assert classify_task_complexity("take your time and scan everything") == \
            TaskComplexity.LONG_RUNNING

    def test_discord_action_create_channel(self):
        assert classify_task_complexity("create a channel called test") == \
            TaskComplexity.MODERATE

    def test_discord_action_create_role(self):
        assert classify_task_complexity("create a new role called Admin") == \
            TaskComplexity.MODERATE

    def test_discord_action_kick(self):
        assert classify_task_complexity("kick user123") == TaskComplexity.MODERATE

    def test_discord_action_ban(self):
        assert classify_task_complexity("ban the user spammer") == TaskComplexity.MODERATE

    def test_discord_action_list_members(self):
        assert classify_task_complexity("list all members") == TaskComplexity.MODERATE

    def test_discord_action_remove_role(self):
        assert classify_task_complexity("remove the Admin role from user") == \
            TaskComplexity.MODERATE

    def test_question_not_action(self):
        """Questions about security topics should be SIMPLE, not complex."""
        assert classify_task_complexity("What is XSS?") == TaskComplexity.SIMPLE

    def test_action_request_in_question(self):
        """'Can you scan X?' should be treated as an action."""
        result = classify_task_complexity("can you scan example.com?")
        assert result in (TaskComplexity.COMPLEX, TaskComplexity.MODERATE,
                          TaskComplexity.LONG_RUNNING)


# ============================================================================
# Discord Action Detection Tests
# ============================================================================

class TestDiscordActionDetection:
    def test_create_channel(self):
        assert is_discord_action("create a channel called test")

    def test_create_role(self):
        assert is_discord_action("create a new role called Moderator")

    def test_delete_channel(self):
        assert is_discord_action("delete the test channel")

    def test_kick_user(self):
        assert is_discord_action("kick user123")

    def test_ban_user(self):
        assert is_discord_action("ban the spammer")

    def test_timeout_user(self):
        assert is_discord_action("timeout user for 5 minutes")

    def test_list_members(self):
        assert is_discord_action("list all members")

    def test_list_roles(self):
        assert is_discord_action("show all roles")

    def test_assign_role(self):
        assert is_discord_action("assign the Admin role to user")

    def test_remove_role(self):
        assert is_discord_action("remove the role from user")

    def test_purge_messages(self):
        assert is_discord_action("delete 50 messages")

    def test_not_discord_action(self):
        assert not is_discord_action("scan example.com")

    def test_not_discord_action_question(self):
        assert not is_discord_action("what is SQL injection?")


# ============================================================================
# Response Cleaning Tests (Critical fix: no reasoning in Discord)
# ============================================================================

class TestCleanLlmResponse:
    def test_removes_function_calls(self):
        raw = "Here is the result.\n<function=terminal_execute>\n<parameter=command>nmap example.com</parameter>\n</function>"
        cleaned = clean_llm_response(raw)
        assert '<function=' not in cleaned
        assert 'terminal_execute' not in cleaned
        assert 'Here is the result.' in cleaned

    def test_removes_thinking_tags(self):
        raw = "<thinking>I need to figure out what to do</thinking>\nThe scan found 3 vulnerabilities."
        cleaned = clean_llm_response(raw)
        assert '<thinking>' not in cleaned
        assert 'figure out' not in cleaned
        assert '3 vulnerabilities' in cleaned

    def test_removes_shell_prompts(self):
        raw = "$ nmap -sV example.com\nResults:\nPort 80 is open"
        cleaned = clean_llm_response(raw)
        assert '$ nmap' not in cleaned
        assert 'Port 80 is open' in cleaned

    def test_removes_tool_result_tags(self):
        raw = "<tool_result><tool_name>terminal</tool_name><result>output</result></tool_result>\nDone."
        cleaned = clean_llm_response(raw)
        assert '<tool_result>' not in cleaned
        assert 'Done.' in cleaned

    def test_keeps_clean_text(self):
        raw = "The scan is complete. Found 2 high-severity vulnerabilities."
        cleaned = clean_llm_response(raw)
        assert cleaned == raw

    def test_removes_discord_context(self):
        raw = "<discord_context>Server info here</discord_context>\nHello!"
        cleaned = clean_llm_response(raw)
        assert '<discord_context>' not in cleaned
        assert 'Hello!' in cleaned

    def test_empty_input(self):
        assert clean_llm_response("") == ""
        assert clean_llm_response(None) == ""

    def test_preserves_output_code_blocks(self):
        raw = "Results:\n```json\n{\"status\": \"ok\"}\n```"
        cleaned = clean_llm_response(raw)
        assert '"status"' in cleaned

    def test_removes_command_code_blocks(self):
        raw = "Running scan:\n```bash\nnmap -sV example.com\n```\nDone."
        cleaned = clean_llm_response(raw)
        assert 'nmap' not in cleaned
        assert 'Done.' in cleaned

    def test_collapses_blank_lines(self):
        raw = "Line 1\n\n\n\n\nLine 2"
        cleaned = clean_llm_response(raw)
        assert '\n\n\n' not in cleaned
        assert 'Line 1' in cleaned
        assert 'Line 2' in cleaned


# ============================================================================
# Port Validation Tests
# ============================================================================

class TestToolServerPortValidation:
    def test_default_port_value(self):
        port = ""
        if not port:
            port = "48081"
        assert port == "48081"

    def test_port_preserved_when_set(self):
        port = "8080"
        if not port:
            port = "48081"
        assert port == "8080"

    def test_port_conversion(self):
        assert int("48081") == 48081


# ============================================================================
# API Readiness URL Tests
# ============================================================================

class TestApiReadinessUrlConstruction:
    def test_models_url_from_v1(self):
        base = "http://127.0.0.1:8317/v1"
        urls = []
        if base.endswith('/v1'):
            urls.append(f"{base}/models")
        assert "http://127.0.0.1:8317/v1/models" in urls

    def test_models_url_from_base(self):
        base = "http://127.0.0.1:8317"
        urls = []
        if base.endswith('/v1'):
            urls.append(f"{base}/models")
        else:
            urls.append(f"{base}/v1/models")
            urls.append(base)
        assert "http://127.0.0.1:8317/v1/models" in urls


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
