"""The ``f`` flag store.

radare2 keeps flags purely in the session; IDA keeps names in the database.
idare2 defaults to the IDA interpretation -- ``f name @ addr`` renames the
location for everyone, including the GUI analyst -- because operating on the
shared database is the whole point.  ``e ida.flags.write=false`` (or a
read-only session) falls back to session-local flags.

The store is seeded from IDA's names lazily, so ``@ name`` resolution and
``f`` listings do not need a round trip per lookup.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import dataclass


@dataclass(frozen=True)
class Flag:
    name: str
    ea: int
    size: int = 1
    #: True when the flag exists only in this session, not in the IDB.
    local: bool = False


class FlagStore:
    def __init__(self) -> None:
        self._by_name: dict[str, Flag] = {}
        self._by_ea: dict[int, list[str]] = {}
        self._seeded = False

    @property
    def seeded(self) -> bool:
        return self._seeded

    def seed(self, pairs: Iterable[tuple[int, str]]) -> None:
        """Populate from IDA's name table.  Existing session flags win."""
        for ea, name in pairs:
            if not name or name in self._by_name:
                continue
            flag = Flag(name=name, ea=int(ea))
            self._by_name[name] = flag
            self._by_ea.setdefault(int(ea), []).append(name)
        self._seeded = True

    def invalidate(self) -> None:
        """Drop everything so the next access re-seeds (the IDB changed)."""
        self._by_name.clear()
        self._by_ea.clear()
        self._seeded = False

    def add(self, name: str, ea: int, size: int = 1, *, local: bool = False) -> Flag:
        existing = self._by_name.get(name)
        if existing is not None:
            self._by_ea.get(existing.ea, []).remove(name)
        flag = Flag(name=name, ea=int(ea), size=size, local=local)
        self._by_name[name] = flag
        self._by_ea.setdefault(int(ea), []).append(name)
        return flag

    def remove(self, name: str) -> Flag | None:
        flag = self._by_name.pop(name, None)
        if flag is not None:
            names = self._by_ea.get(flag.ea, [])
            if name in names:
                names.remove(name)
            if not names:
                self._by_ea.pop(flag.ea, None)
        return flag

    def lookup(self, name: str) -> int | None:
        flag = self._by_name.get(name)
        return None if flag is None else flag.ea

    def at(self, ea: int) -> list[Flag]:
        return [self._by_name[n] for n in self._by_ea.get(int(ea), []) if n in self._by_name]

    def all(self) -> Iterator[Flag]:
        return iter(sorted(self._by_name.values(), key=lambda f: (f.ea, f.name)))

    def __len__(self) -> int:
        return len(self._by_name)
