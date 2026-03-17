# SPDX-License-Identifier: GPL-3.0-or-later

from fnmatch import fnmatchcase


class PackageFilter:
    def __init__(self) -> None:
        self.include: set[str] = set()
        self.exclude: set[str] = set()
        self.include_source_name: set[str] = set()
        self.exclude_source_name: set[str] = set()
        self.include_binary_packages: set[str] = set()
        self.exclude_binary_packages: set[str] = set()
        self.include_sections: set[str] = set()
        self.exclude_sections: set[str] = set()
        self.include_tags: set[str] = set()
        self.exclude_tags: set[str] = set()

    def package_allowed(
        self,
        source_name: str,
        package_name: str | None = None,
        section: str | None = None,
        tags: set[str] | None = None,
    ) -> bool:
        names = {source_name}
        if package_name:
            names.add(package_name)

        if self.include and not self._matches_any_glob(names, self.include):
            return False

        if self.exclude and self._matches_any_glob(names, self.exclude):
            return False

        if self.include_source_name and source_name not in self.include_source_name:
            return False

        if self.exclude_source_name and source_name in self.exclude_source_name:
            return False

        if package_name:
            if (
                self.include_binary_packages
                and package_name not in self.include_binary_packages
            ):
                return False

            if (
                self.exclude_binary_packages
                and package_name in self.exclude_binary_packages
            ):
                return False

        if section:
            if self.include_sections and not any(
                s == section for s in self.include_sections
            ):
                return False

            if self.exclude_sections and any(
                s == section for s in self.exclude_sections
            ):
                return False

        if tags:
            tags = self._split_tags(tags)

            if self.include_tags and not any(t in tags for t in self.include_tags):
                return False

            if self.exclude_tags and any(t in tags for t in self.exclude_tags):
                return False

        return True

    def _split_tags(self, tags: set[str]) -> set[str]:
        return tags.union({t.split("::")[0] for t in tags})

    def _matches_any_glob(self, values: set[str], patterns: set[str]) -> bool:
        return any(
            fnmatchcase(value, pattern) for value in values for pattern in patterns
        )
