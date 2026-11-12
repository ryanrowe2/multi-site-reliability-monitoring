# Operations and deployment considerations

## Historical workflow

The inspected original source defines two CLI modes, uses cURL HTTPS probing, holds state in JSON, and prints notifications to stdout. Supporting publication-planning material describes a cPanel uptime cron job scheduled at minutes **0 and 30**. The source alone does not establish whether every scheduled run completed, whether notification emails were delivered, or whether integrity mode was separately scheduled.

The original source processes domains serially and sets a 15-second request timeout. Worst-case probe latency can add up across a large inventory and should be considered when selecting a cron interval. No real-world runtime profile or outage history was available for this assessment.

## Safe demo scheduling

For a local educational experiment only, schedule the **offline** CLI using prewritten synthetic fixtures, for example:

```cron
0,30 * * * * cd /path/to/multi-site-reliability-monitoring && /usr/bin/php bin/monitor.php uptime --config config/demo.json --responses examples/responses/healthy.json --state var/demo-uptime-state.json >> var/offline-example.log 2>&1
```

This example is not an employer production command. It contacts no websites and sends no emails. Avoid a fixed `--at` in cron: the CLI will use the current UTC time if no timestamp is supplied. Store state in a private, writable directory and protect fixture/state permissions.

## Operational fault tolerance

Exit code **2** indicates that backlog pressure caused an existing batch to drain **without evaluating the new observation**; a scheduler must rerun that observation and must not label it as a successful scan. Run `php bin/monitor.php flush --mode uptime --state var/demo-uptime-state.json` to replay pending events without monitoring inputs. Exit code **1** indicates a monitoring process error (bad input, unreadable state, invalid timestamp, failed persistence). Exit code **0** means the offline scan completed; synthetic failures are represented as events. This avoids confusing monitored-site failures with failures of the monitoring tool itself.

A future production deployment would require authorized host configuration, SSRF/DNS-rebinding protections for real network probing, secure secrets and notifications, concurrency-safe distributed state, a scheduler with runtime budgets, and an event-delivery retry strategy. None of these is implied by this standalone demonstration.

The public release stages events to a persistent outbox before stdout. If stdout cannot be written, the batch is released for retry; if the process dies before confirming successful output, the lease expires after 120 seconds and a subsequent run can replay. It is possible to receive duplicate events after a crash or persistence failure. Redirect observations are explicitly unverified, and removed inventory targets generate `retired`, not `recovered`. Any downstream scheduler or notification delivery service must implement its own health checking and acknowledgments.
