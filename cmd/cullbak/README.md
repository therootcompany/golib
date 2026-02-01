# Cull Backups

Culls backups on a monthly, weekly, and daily schedule

Keeps 1 backup for

- each iso week, forever
- each day for the last 2 weeks
- each backup, for the last 7 days

The backups are done on whatever schedule by some other process.

This process is called on the backups folder, after each backup completes.

## Usage

```sh
for my_dir in $(ls -d /mnt/backups/*); do
    cull-backups --dry-run --keep-dailies 35 --exts 'tar.zst,sql.zst,tar.xz,sql.xz,' "/mnt/backups/${my_dir}"
done
```

```text
/mnt/
└── backups/
    ├── proj-y/
    │   ├── monthly/
    │   ├── weekly/
    │   ├── daily/
    │   └── 2024-01-01_00.00.00.tar.xz
    ├── project-x/
    │   ├── monthly/
    │   ├── weekly/
    │   ├── daily/
    │   └── 2024-01-01_00.00.00.tar.xz
    └── projectfoo-z/
        ├── monthly/
        ├── weekly/
        ├── daily/
        └── 2024-01-01_00.00.00.tar.xz
```
