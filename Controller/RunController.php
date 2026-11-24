<?php

namespace Kanboard\Plugin\Gumshoe\Controller;

use Kanboard\Controller\BaseController;
use Kanboard\Plugin\Gumshoe\Run\RunLog;

final class RunController extends BaseController
{
    public function index(): void
    {
        $log = new RunLog($this->db->getConnection());
        $runs = $log->recent();
        foreach ($runs as &$run) {
            $counts = json_decode($run['counts'], true);
            $run['summary'] = [];
            foreach (['complete', 'partial', 'inaccessible', 'out_of_watch', 'no_lockfile', 'coverage_gaps'] as $key) {
                if (isset($counts[$key])) {
                    $run['summary'][] = (int) $counts[$key].' '.str_replace('_', ' ', $key);
                }
            }
            foreach (['listed_owners' => 'Owners listed', 'failed_owners' => 'Owners failed'] as $key => $label) {
                if (isset($counts[$key]) && is_array($counts[$key])) {
                    $run['summary'][] = $label.' '.count($counts[$key]);
                }
            }
        }
        unset($run);

        $this->response->html($this->helper->layout->config('Gumshoe:run/index', [
            'title' => 'Gumshoe · Run log',
            'runs' => $runs,
        ]));
    }
}
