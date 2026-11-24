<?php

namespace Kanboard\Plugin\Gumshoe\Inventory;

final class Differ
{
    /**
     * Compare distinct versions per package and lockfile. Install count and scope
     * do not change which versions are present in a lockfile.
     *
     * @param list<array{ecosystem: string, name: string, path: string, version: string}> $old
     * @param list<array{ecosystem: string, name: string, path: string, version: string}> $new
     * @return list<array{kind: string, ecosystem: string, name: string, path: string, from_version: ?string, to_version: ?string}>
     */
    public static function diff(array $old, array $new): array
    {
        $before = self::group($old);
        $after = self::group($new);
        $changes = [];

        foreach ($before + $after as $key => $group) {
            $oldVersions = $before[$key]['versions'] ?? [];
            $newVersions = $after[$key]['versions'] ?? [];
            $removed = array_values(array_diff_key($oldVersions, $newVersions));
            $added = array_values(array_diff_key($newVersions, $oldVersions));
            $identity = $group['identity'];

            if (count($removed) === 1 && count($added) === 1) {
                $changes[] = ['kind' => 'changed'] + $identity + [
                    'from_version' => $removed[0], 'to_version' => $added[0],
                ];
                continue;
            }
            foreach ($removed as $version) {
                $changes[] = ['kind' => 'removed'] + $identity + ['from_version' => $version, 'to_version' => null];
            }
            foreach ($added as $version) {
                $changes[] = ['kind' => 'added'] + $identity + ['from_version' => null, 'to_version' => $version];
            }
        }

        return $changes;
    }

    private static function group(array $rows): array
    {
        $groups = [];
        foreach ($rows as $row) {
            $identity = ['ecosystem' => $row['ecosystem'], 'name' => $row['name'], 'path' => $row['path']];
            $key = serialize($identity);
            $groups[$key]['identity'] ??= $identity;
            $groups[$key]['versions']['v:'.$row['version']] = $row['version'];
        }
        return $groups;
    }
}
