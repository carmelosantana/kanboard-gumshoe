<?php

namespace Kanboard\Plugin\Gumshoe\Inventory;

use Symfony\Component\Yaml\Exception\ParseException;
use Symfony\Component\Yaml\Yaml as SymfonyYaml;
use UnexpectedValueException;

final class Yaml
{
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
    private int $remainingNodes = Limits::MAX_YAML_NODES;
    private int $nodes = 0;
    /** @var array<string, int> Expanded sizes, with zero for anchors still open. */
    private array $anchors = [];
    /** @var list<array{name: string, start: int, indent: int, depth: int, indentless: bool}> */
    private array $openAnchors = [];
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
            if ($this->quote === null && $this->flowDepth === 0) {
                $content = substr($line, $indent);
                if ($content === '' || $content[0] === '#' || trim($content, " \t") === '') {
                    continue;
                }
                $this->closeBlockAnchors($indent, $content[0] === '-' && str_contains(" \t", $content[1] ?? ' '));
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
        $mappingValue = false;
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
                $i += $this->scanReference($line, $i, $valueIndent, $mappingValue);
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
                $mappingValue = false;
                ++$this->nodes;
                continue;
            }
            if ($atNode && ($char === '[' || $char === '{')) {
                ++$this->flowDepth;
                ++$this->nodes;
                continue;
            }
            if ($this->flowDepth > 0 && ($char === ']' || $char === '}')) {
                $this->closeFlowAnchors();
                --$this->flowDepth;
                $atNode = false;
                $quotedKey = false;
                continue;
            }
            if (($this->flowDepth > 0 && $char === ',')
                || ($char === ':' && ($quotedKey || str_contains(" \t", $next)
                    || ($this->flowDepth > 0 && str_contains('[]{},', $next))))) {
                if ($char === ',') {
                    $this->closeFlowAnchors();
                }
                $atNode = true;
                $quotedKey = false;
                $valueIndent = $sequenceIndent;
                $mappingValue = $char === ':';
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

    private function scanReference(string $line, int $offset, int $indent, bool $mappingValue): int
    {
        if (++$this->referenceCount > Limits::MAX_YAML_REFERENCES) {
            throw new UnexpectedValueException();
        }

        $delimiters = $this->flowDepth > 0 ? " \t,[]{}" : " \t";
        $length = strcspn($line, $delimiters, $offset + 1);
        $name = substr($line, $offset + 1, $length);
        if ($line[$offset] === '&') {
            if (isset($this->anchors[$name])) {
                throw new UnexpectedValueException();
            }
            $tail = ltrim(substr($line, $offset + 1 + $length), " \t");
            $this->anchors[$name] = 0;
            $this->openAnchors[] = [
                'name' => $name,
                'start' => $this->nodes,
                'indent' => $indent,
                'depth' => $this->flowDepth,
                'indentless' => $mappingValue && ($tail === '' || $tail[0] === '#'),
            ];
        } else {
            // Charge the alias as the full target span, including aliases already
            // charged inside it. An unfinished anchor cannot be an alias target.
            $size = $this->anchors[$name] ?? 0;
            if ($size === 0 || $size > $this->remainingNodes - $this->nodes) {
                throw new UnexpectedValueException();
            }
            $this->nodes += $size;
        }
        return $length;
    }

    private function closeBlockAnchors(int $indent, bool $sequenceItem): void
    {
        while (($anchor = end($this->openAnchors)) !== false) {
            if ($indent > $anchor['indent']
                || ($indent === $anchor['indent'] && $sequenceItem && $anchor['indentless'])) {
                break;
            }
            $this->closeAnchor();
        }
    }

    private function closeFlowAnchors(): void
    {
        while (($anchor = end($this->openAnchors)) !== false && $anchor['depth'] === $this->flowDepth) {
            $this->closeAnchor();
        }
    }

    private function closeAnchor(): void
    {
        $anchor = array_pop($this->openAnchors);
        if ($this->nodes === $anchor['start']) {
            ++$this->nodes;
        }
        $this->anchors[$anchor['name']] = $this->nodes - $anchor['start'];
    }

    private function chargeDocument(): void
    {
        while ($this->openAnchors !== []) {
            $this->closeAnchor();
        }
        if ($this->nodes > $this->remainingNodes) {
            throw new UnexpectedValueException();
        }
        $this->remainingNodes -= $this->nodes;
        $this->nodes = 0;
        $this->anchors = [];
    }
}
