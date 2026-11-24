<?php

namespace Kanboard\Plugin\Gumshoe\Secrets;

final class Redactor
{
    public static function redact(#[\SensitiveParameter] string $text): string
    {
        return preg_replace('/gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}/', '[redacted]', $text);
    }
}
