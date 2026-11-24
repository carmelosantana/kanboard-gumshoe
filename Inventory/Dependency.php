<?php

namespace Kanboard\Plugin\Gumshoe\Inventory;

final readonly class Dependency
{
    public const QUERY_PACKAGE = 'package';
    public const QUERY_COMMIT = 'commit';
    public const QUERY_NONE = 'none';

    public function __construct(
        public string $ecosystem,
        public string $name,
        public ?string $version,
        public string $scope,
        public ?string $source,
        public string $query_type,
        public ?string $registry_evidence,
        public bool $evidence_inferred = false,
    ) {
    }
}
