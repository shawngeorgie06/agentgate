import json
import os
import stat

from broker.imessage_style import DECAY_AT, MIN_MESSAGES, TextingStyle


def learn(style, *texts):
    for text in texts:
        style.observe(text)


def test_no_notes_until_enough_messages(tmp_path):
    style = TextingStyle(tmp_path / 'style.json')
    learn(style, *['lol ok'] * (MIN_MESSAGES - 1))
    assert style.count() == MIN_MESSAGES - 1
    assert style.notes() == ''
    style.observe('lol ok')
    assert style.notes() != ''


def test_notes_describe_short_lowercase_texts_with_slang(tmp_path):
    style = TextingStyle(tmp_path / 'style.json')
    learn(style, 'lol whats up', 'idk tbh', 'ya lol', 'u free rn', 'lol same', 'idk lol')
    notes = style.notes()
    assert 'short' in notes
    assert 'all lowercase' in notes
    assert 'rarely ends with a period' in notes
    assert 'lol' in notes and 'idk' in notes


def test_notes_describe_formal_texts(tmp_path):
    style = TextingStyle(tmp_path / 'style.json')
    learn(style, *['Could you please summarize my unread email from this morning for me.'] * 6)
    notes = style.notes()
    assert 'normal capitalization' in notes
    assert 'ends sentences with periods' in notes
    assert 'lol' not in notes


def test_notes_pick_up_emoji_and_exclamation(tmp_path):
    style = TextingStyle(tmp_path / 'style.json')
    learn(style, *['omg yes!! 😂'] * 6)
    notes = style.notes()
    assert 'emoji' in notes and 'exclamation' in notes


def test_only_counts_are_stored_never_message_text(tmp_path):
    path = tmp_path / 'style.json'
    style = TextingStyle(path)
    learn(style, *['lol zanzibarquux secret plan'] * 6)
    raw = path.read_bytes()
    assert b'zanzibarquux' not in raw and b'secret' not in raw and b'plan' not in raw
    assert b'lol' in raw
    assert 'zanzibarquux' not in style.notes()
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


def test_style_persists_and_resets(tmp_path):
    path = tmp_path / 'style.json'
    learn(TextingStyle(path), *['lol ok'] * 6)
    again = TextingStyle(path)
    assert again.count() == 6 and again.notes() != ''
    again.reset()
    assert again.count() == 0 and again.notes() == ''
    assert TextingStyle(path).count() == 0


def test_corrupt_or_unsafe_file_starts_fresh(tmp_path):
    path = tmp_path / 'style.json'
    path.write_text('{not json')
    path.chmod(0o600)
    assert TextingStyle(path).count() == 0
    path.write_text(json.dumps({'messages': 'many'}))
    assert TextingStyle(path).count() == 0
    learn(TextingStyle(path), *['lol ok'] * 6)
    path.chmod(0o644)
    assert TextingStyle(path).count() == 0


def test_ignores_empty_and_bounds_input(tmp_path):
    style = TextingStyle(tmp_path / 'style.json')
    style.observe('')
    style.observe('   ')
    style.observe(None)
    assert style.count() == 0
    style.observe('x' * 100000)
    assert style.count() == 1


def test_reset_reports_failure_when_file_cannot_be_removed(tmp_path):
    path = tmp_path / 'style.json'
    style = TextingStyle(path)
    learn(style, *['lol ok'] * 6)
    path.unlink()
    path.mkdir()
    (path / 'keep').write_text('x')
    assert style.reset() is False
    # The old style is still on disk, so it stays visible and the user can retry.
    assert style.count() == 6


def test_reset_succeeds_with_or_without_a_file(tmp_path):
    style = TextingStyle(tmp_path / 'style.json')
    assert style.reset() is True
    learn(style, 'lol')
    assert style.reset() is True


def test_old_habits_fade_so_recent_texts_dominate(tmp_path):
    style = TextingStyle(tmp_path / 'style.json')
    learn(style, *['Hello there, how are you doing today.'] * DECAY_AT)
    assert style.count() <= DECAY_AT
    learn(style, *['lol ya'] * DECAY_AT)
    notes = style.notes()
    assert 'all lowercase' in notes and 'lol' in notes
