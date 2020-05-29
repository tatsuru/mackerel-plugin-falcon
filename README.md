mackerel-plugin-falcon
======================

Ffalcon Endpoint Protection custom metrics plugin for mackerel.io agent.

## Synopsis

```shell
mackerel-plugin-falcon
```

## Example of mackerel-agent.conf

```
[plugin.metrics.falcon]
command = "/path/to/mackerel-plugin-falcon"
```

## Requirements

WARNING: This might create security holes.

```
sudo chmod 755 /Library/CS/falconctl
```



