<?php

namespace GlpiPlugin\Sso\Console;

use Glpi\Console\AbstractCommand;
use GlpiPlugin\Sso\Doctor;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

if (!defined('GLPI_ROOT')) {
    die('Sorry. You can\'t access this file directly');
}

/**
 * `php bin/console plugins:sso:doctor` — diagnóstico operativo del plugin.
 * Exit code 0 sin fallas, 1 con al menos un FAIL (usable desde monitoreo).
 */
class DoctorCommand extends AbstractCommand
{
    protected function configure(): void
    {
        parent::configure();

        $this->setName('plugins:sso:doctor');
        $this->setDescription('Diagnóstico del plugin SSO: DB, crons, config e IdPs');
        $this->addOption('bundle', null, InputOption::VALUE_NONE, 'Emitir el support bundle JSON redactado en lugar del reporte');
        $this->addOption('no-network', null, InputOption::VALUE_NONE, 'No hacer probes HTTP a los IdPs');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $with_network = !$input->getOption('no-network');

        if ($input->getOption('bundle')) {
            $output->writeln(json_encode(
                Doctor::bundle($with_network),
                JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
            ));
            return 0;
        }

        $checks   = Doctor::run($with_network);
        $failures = 0;
        $section  = '';

        foreach ($checks as $check) {
            if ($check['section'] !== $section) {
                $section = $check['section'];
                $output->writeln('');
                $output->writeln('<comment>[' . strtoupper($section) . ']</comment>');
            }
            $tag = match ($check['status']) {
                Doctor::OK   => '<info> OK </info>',
                Doctor::WARN => '<comment>WARN</comment>',
                default      => '<error>FAIL</error>',
            };
            if ($check['status'] === Doctor::FAIL) {
                $failures++;
            }
            $output->writeln(sprintf(' %s  %-38s %s', $tag, $check['name'], $check['detail']));
        }

        $output->writeln('');
        $output->writeln($failures === 0 ? '<info>Sin fallas.</info>' : "<error>$failures falla(s).</error>");
        return $failures === 0 ? 0 : 1;
    }
}
