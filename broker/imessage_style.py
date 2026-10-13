"""Learn how the user texts from their /agent messages, keeping only counts, never message text."""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import stat
import tempfile

MIN_MESSAGES = 5
# Past this many messages every count is halved, so recent texts outweigh old habits.
DECAY_AT = 200
OBSERVE_LIMIT = 2000
FILE_LIMIT = 8192
COUNTERS = ('messages', 'words', 'no_caps', 'lower_start', 'ends_period', 'emoji', 'exclaim', 'stretched')
# Only these words are ever counted, so arbitrary words from a message can never reach the file.
SLANG = ('lol', 'lmao', 'haha', 'omg', 'idk', 'tbh', 'ngl', 'rn', 'fr', 'u', 'ur', 'ya', 'yea', 'yeah',
         'yep', 'nah', 'k', 'kk', 'pls', 'plz', 'thx', 'ty', 'bro', 'dude', 'btw', 'imo', 'smh', 'wyd', 'hbu')

_WORD = re.compile(r"[a-z']+")
_EMOJI = re.compile('[\U0001F300-\U0001FAFF☀-➿]')


def _empty():
    return {**{name: 0 for name in COUNTERS}, 'slang': {}}


def _valid(value):
    if not isinstance(value, dict) or set(value) != {*COUNTERS, 'slang'}:
        return False
    if not all(type(value[name]) is int and value[name] >= 0 for name in COUNTERS):
        return False
    slang = value['slang']
    return isinstance(slang, dict) and all(
        word in SLANG and type(count) is int and count > 0 for word, count in slang.items())


class TextingStyle:
    """Decaying counts of the user's texting habits, saved 0600, turned into short style notes."""

    def __init__(self, path):
        self._path = Path(path)
        self._data = self._load()

    def count(self):
        return self._data['messages']

    def observe(self, text):
        if not isinstance(text, str) or not text.strip():
            return
        text = text.strip()[:OBSERVE_LIMIT]
        data = self._data
        words = _WORD.findall(text.lower())
        letters = [ch for ch in text if ch.isalpha()]
        data['messages'] += 1
        data['words'] += len(text.split())
        data['no_caps'] += not any(ch.isupper() for ch in letters)
        data['lower_start'] += bool(letters) and letters[0].islower()
        data['ends_period'] += text.endswith('.') and not text.endswith('...')
        data['emoji'] += bool(_EMOJI.search(text))
        data['exclaim'] += '!' in text
        data['stretched'] += any(mark in text for mark in ('!!', '??', '...'))
        for word in set(words):
            if word in SLANG:
                data['slang'][word] = data['slang'].get(word, 0) + 1
        if data['messages'] >= DECAY_AT:
            for name in COUNTERS:
                data[name] //= 2
            data['slang'] = {w: c // 2 for w, c in data['slang'].items() if c // 2 > 0}
        self._save()

    def reset(self):
        """Forget the style. Returns False, keeping the old counts, if they could not be cleared."""
        old, self._data = self._data, _empty()
        try:
            self._path.unlink()
            return True
        except FileNotFoundError:
            return True
        except OSError:
            # Could not remove it, so overwrite it with empty counts instead.
            if self._save():
                return True
            self._data = old
            return False

    def notes(self):
        """A short description built only from fixed phrases, or '' until there is enough to go on."""
        data = self._data
        n = data['messages']
        if n < MIN_MESSAGES:
            return ''
        ratio = lambda name: data[name] / n
        average = round(data['words'] / n)
        parts = []
        if average < 6:
            parts.append(f'very short texts (about {average} words)')
        elif average < 15:
            parts.append(f'short texts (about {average} words)')
        else:
            parts.append('longer, full-sentence messages')
        if ratio('no_caps') >= 0.6:
            parts.append('writes in all lowercase')
        elif ratio('lower_start') >= 0.6:
            parts.append('usually skips the capital letter at the start')
        else:
            parts.append('uses normal capitalization')
        if ratio('ends_period') < 0.2:
            parts.append('rarely ends with a period')
        elif ratio('ends_period') > 0.6:
            parts.append('ends sentences with periods')
        if ratio('emoji') >= 0.3:
            parts.append('often uses emoji')
        elif ratio('emoji') < 0.05:
            parts.append('rarely uses emoji')
        if ratio('exclaim') >= 0.3:
            parts.append('uses exclamation marks a lot')
        if ratio('stretched') >= 0.2:
            parts.append("stretches punctuation like '...' or '!!'")
        common = sorted((w for w, c in data['slang'].items() if c >= max(2, 0.15 * n)),
                        key=lambda w: (-data['slang'][w], w))[:5]
        if common:
            parts.append('often says ' + ', '.join(common))
        return '; '.join(parts)

    def _load(self):
        try:
            fd = os.open(self._path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
        except OSError:
            return _empty()
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
                return _empty()
            raw = os.read(fd, FILE_LIMIT + 1)
        except OSError:
            return _empty()
        finally:
            os.close(fd)
        try:
            value = json.loads(raw) if len(raw) <= FILE_LIMIT else None
        except (ValueError, UnicodeDecodeError):
            return _empty()
        return value if _valid(value) else _empty()

    def _save(self):
        """Best effort: a failed write only means the style is learned again later."""
        try:
            self._path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=self._path.parent, prefix='.imessage-style-', suffix='.tmp')
        except OSError:
            return False
        try:
            with os.fdopen(fd, 'wb') as handle:
                handle.write(json.dumps(self._data, sort_keys=True).encode())
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, self._path)
            return True
        except OSError:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            return False
