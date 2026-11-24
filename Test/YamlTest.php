<?php

namespace Kanboard\Plugin\Gumshoe\Test;

use Kanboard\Plugin\Gumshoe\Inventory\ParseResult;
use Kanboard\Plugin\Gumshoe\Inventory\Yaml;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Yaml\Yaml as SymfonyYaml;

require_once __DIR__.'/bootstrap.php';

final class YamlTest extends TestCase
{
    public static function rejectedFiles(): array
    {
        return [
            'PHP object tag' => ['yaml-php-object.yaml'],
            'PHP constant tag' => ['yaml-php-const.yaml'],
            'binary tag' => ['yaml-binary.yaml'],
            'alias count exceeds 1000' => ['yaml-alias-count.yaml'],
            'logical node count exceeds 500000' => ['yaml-alias-bomb.yaml'],
        ];
    }

    /** @dataProvider rejectedFiles */
    public function testRefusesUnsafeYaml(string $file): void
    {
        $result = Yaml::parseDocuments($this->fixture($file));

        self::assertInstanceOf(ParseResult::class, $result);
        self::assertSame('parse_error', $result->status);
        self::assertSame([], $result->deps);
    }

    public function testPinsSymfonyFlagsZeroBehaviour(): void
    {
        self::assertSame(['lockfileVersion' => '9.0', 'settings' => null],
            SymfonyYaml::parse($this->fixture('yaml-php-object.yaml'), 0));
        self::assertSame(['autoInstallPeers' => null],
            SymfonyYaml::parse($this->fixture('yaml-php-const.yaml'), 0)['settings']);
        self::assertSame(['blob' => 'Gumshoe fixture: not a real payload'],
            SymfonyYaml::parse($this->fixture('yaml-binary.yaml'), 0)['settings']);
    }

    public function testBlockScalarDashesStayInOneDocument(): void
    {
        $documents = Yaml::parseDocuments($this->fixture('yaml-block-scalar-dashes.yaml'));

        self::assertIsArray($documents);
        self::assertCount(1, $documents);
        self::assertSame(2, substr_count($documents[0]['packages']['is-positive@3.1.0']['deprecated'], "---\n"));
    }

    public function testAcceptsNestedAnchorsInBlockAndFlowCollections(): void
    {
        $documents = Yaml::parseDocuments(<<<'YAML'
            base: &base
            - first
            - second
            nested: &nested
              flow: [&inner [*base, third], *inner]
            copy: *nested
            YAML);

        $base = ['first', 'second'];
        $inner = [$base, 'third'];
        $nested = ['flow' => [$inner, $inner]];
        self::assertSame([['base' => $base, 'nested' => $nested, 'copy' => $nested]], $documents);
    }

    public function testOnlyTagsInYamlSyntaxAreRefused(): void
    {
        $documents = Yaml::parseDocuments(<<<'YAML'
            a: "!tag"
            b: 'it''s !!binary'
            c: |-
              !php/const PHP_INT_MAX
            d: plain!text
            e: [&one hi, *one]
            f: 'a
              ---
              !tag'
            # !comment
            YAML);

        self::assertSame([[
            'a' => '!tag',
            'b' => "it's !!binary",
            'c' => '!php/const PHP_INT_MAX',
            'd' => 'plain!text',
            'e' => ['hi', 'hi'],
            'f' => 'a --- !tag',
        ]], $documents);

        foreach ([
            'a: {b: !local x}',
            'a: {b:[!!binary SGk=]}',
            'a: &x !<tag:yaml.org,2002:str> x',
            "a: \v!!binary SGk=",
            "a: |2-\n  !tag\nb: !!binary SGk=",
            '--- !local',
        ] as $input) {
            $result = Yaml::parseDocuments($input);
            self::assertInstanceOf(ParseResult::class, $result);
            self::assertSame('parse_error', $result->status);
        }
    }

    private function fixture(string $file): string
    {
        return file_get_contents(__DIR__.'/fixtures/hostile/'.$file);
    }
}
