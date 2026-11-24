<?php

namespace Kanboard\Plugin\Gumshoe\Inventory;

use Symfony\Component\Yaml\Exception\ParseException;
use Symfony\Component\Yaml\Yaml as SymfonyYaml;
use UnexpectedValueException;

final class Yaml
{
    private const MAX_REFERENCES = 1_000;
    private const MAX_NODES = 500_000;

    /** @return list<mixed>|ParseResult */
    public static function parseDocuments(string $contents): array|ParseResult
    {
        if (strlen($contents) > Limits::MAX_FILE_BYTES) {
            return new ParseResult([], 'too_large');
        }
        if (preg_match('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', $contents) === 1) {
            return new ParseResult([], 'parse_error');
        }

        $contents = str_replace(["\r\n", "\r"], "\n", $contents);

        try {
            $guard = new self();
            $documents = [];
            foreach ($guard->documentSlices($contents) as $document) {
                $documents[] = SymfonyYaml::parse($document, 0);
            }
            return $documents;
        } catch (ParseException | UnexpectedValueException) {
            return new ParseResult([], 'parse_error');
        }
    }

    private int $referenceCount = 0;
    private int $remainingNodes = self::MAX_NODES;
    private int $nodes = 0;
    private array $aliases = [];
    private array $anchors = [];
    private ?string $quote = null;
    private int $flowDepth = 0;
    private ?int $blockIndent = null;
    private bool $inferBlockIndent = false;

    /** @return \Generator<string> */
    private function documentSlices(string $contents): \Generator
    {
        $start = 0;
        $length = strlen($contents);
        for ($offset = 0; $offset < $length; $offset = $end + 1) {
            $end = strpos($contents, "\n", $offset);
            $end = $end === false ? $length : $end;
            $line = substr($contents, $offset, $end - $offset);
            if ($offset === $start && str_starts_with($line, "\xEF\xBB\xBF")) {
                $line = substr($line, 3);
            }
            $indent = strspn($line, ' ');
            if ($this->inBlockScalar($line, $indent)) {
                continue;
            }

            if ($line === '---' && $this->quote === null && $this->flowDepth === 0) {
                if ($this->nodes > 0) {
                    $this->chargeDocument();
                    yield substr($contents, $start, $offset - $start);
                }
                $start = $end + 1;
                continue;
            }

            $this->scanLine($line, $indent);
            if ($this->nodes > $this->remainingNodes) {
                throw new UnexpectedValueException();
            }
        }

        if ($this->nodes > 0) {
            $this->chargeDocument();
            yield substr($contents, $start);
        }
    }

    private function inBlockScalar(string $line, int $indent): bool
    {
        if ($this->blockIndent === null) {
            return false;
        }
        if (trim($line, " \t") === '') {
            return true;
        }
        if ($indent < $this->blockIndent) {
            $this->blockIndent = null;
            return false;
        }
        if ($this->inferBlockIndent) {
            $this->blockIndent = $indent;
            $this->inferBlockIndent = false;
        }
        return true;
    }

    private function scanLine(string $line, int $indent): void
    {
        $length = strlen($line);
        $atNode = true;
        $quotedKey = false;
        $sequenceIndent = $indent;
        $valueIndent = $indent;
        $i = $indent;
        if (preg_match('/^---[ \t]+/', $line, $marker) === 1) {
            $i = strlen($marker[0]);
        }

        for (; $i < $length; ++$i) {
            $char = $line[$i];
            $next = $line[$i + 1] ?? ' ';
            if ($this->quote !== null) {
                if (($this->quote === '"' && $char === '\\') || ($this->quote === "'" && $char === "'" && $next === "'")) {
                    ++$i;
                } elseif ($char === $this->quote) {
                    $this->quote = null;
                    $atNode = false;
                    $quotedKey = true;
                }
                continue;
            }

            if ($char === ' ' || $char === "\t") {
                continue;
            }
            if ($char === '#' && ($i === 0 || str_contains(" \t", $line[$i - 1]))) {
                break;
            }

            if ($atNode && $char === '!') {
                throw new UnexpectedValueException();
            }
            if ($atNode && ($char === '&' || $char === '*')) {
                $i += $this->scanReference($line, $i, $char);
                $atNode = $char === '&';
                continue;
            }
            if ($atNode && ($char === "'" || $char === '"')) {
                $this->quote = $char;
                ++$this->nodes;
                continue;
            }
            if ($atNode && $this->flowDepth === 0 && ($char === '|' || $char === '>')
                && preg_match('/[|>]([+-]?[1-9]?|[1-9][+-])(?:[ \t]+(?:#.*)?)?$/A', $line, $block, 0, $i) === 1) {
                $explicit = (int) trim($block[1], '+-');
                $this->blockIndent = $valueIndent + max(1, $explicit);
                $this->inferBlockIndent = $explicit === 0;
                ++$this->nodes;
                break;
            }
            if ($atNode && $this->flowDepth === 0 && ($char === '-' || $char === '?') && str_contains(" \t", $next)) {
                $valueIndent = $i;
                $sequenceIndent = $i + 1 + strspn($line, " \t", $i + 1);
                ++$this->nodes;
                continue;
            }
            if ($atNode && ($char === '[' || $char === '{')) {
                ++$this->flowDepth;
                ++$this->nodes;
                continue;
            }
            if ($this->flowDepth > 0 && ($char === ']' || $char === '}')) {
                --$this->flowDepth;
                $atNode = false;
                $quotedKey = false;
                continue;
            }
            if (($this->flowDepth > 0 && $char === ',')
                || ($char === ':' && ($quotedKey || str_contains(" \t", $next)
                    || ($this->flowDepth > 0 && str_contains('[]{},', $next))))) {
                $atNode = true;
                $quotedKey = false;
                $valueIndent = $sequenceIndent;
                ++$this->nodes;
                continue;
            }

            if ($atNode) {
                ++$this->nodes;
            }
            $atNode = false;
            $quotedKey = false;
        }
    }

    private function scanReference(string $line, int $offset, string $indicator): int
    {
        if (++$this->referenceCount > self::MAX_REFERENCES) {
            throw new UnexpectedValueException();
        }

        $delimiters = $this->flowDepth > 0 ? " \t,[]{}" : " \t";
        $length = strcspn($line, $delimiters, $offset + 1);
        $name = substr($line, $offset + 1, $length);
        ++$this->nodes;
        if ($indicator === '&') {
            // A single definition per name keeps alias expansion acyclic.
            if (isset($this->anchors[$name])) {
                throw new UnexpectedValueException();
            }
            // A simple inline scalar has no descendants to amplify.
            $tail = $offset + 1 + $length;
            $this->anchors[$name] = $this->flowDepth === 0
                && preg_match('/[ \t]+[a-zA-Z0-9][a-zA-Z0-9_.-]*(?:[ \t]+(?:#.*)?)?$/A', $line, $unused, 0, $tail) === 1;
        } else {
            $this->aliases[$name] = ($this->aliases[$name] ?? 0) + 1;
        }
        return $length;
    }

    private function chargeDocument(): void
    {
        // Each original node is copied at most once per path of alias sites leading
        // to it. On an acyclic path, each name is either absent or used at one of
        // its sites. Bound the product before handing any references to Symfony.
        $expanded = $this->nodes;
        foreach ($this->aliases as $name => $count) {
            if ($this->anchors[$name] ?? false) {
                // The lexical budget already counted each alias to this scalar.
                continue;
            }
            if ($expanded > intdiv($this->remainingNodes, 1 + $count)) {
                throw new UnexpectedValueException();
            }
            $expanded *= 1 + $count;
        }
        $this->remainingNodes -= $expanded;
        $this->nodes = 0;
        $this->aliases = [];
        $this->anchors = [];
    }
}
