# Fixtures de BAM

- `system_bam.hve`: hive SYSTEM (o recorte) con al menos una entrada bajo
  `ControlSet001\Services\bam\State\UserSettings\{SID}`. Obtener de una VM de
  prueba con `reg save HKLM\SYSTEM system_bam.hve` (elevado). Documentar aquí
  el SID y un path esperado.
