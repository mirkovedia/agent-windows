# Fixtures de hive regf

- `sample.hve`: un hive con una subclave `Select` que contiene el valor
  `Current` (REG_DWORD). Se genera sin necesidad de privilegios con:

  ```
  reg add "HKCU\Software\TelagemTest\Select" /v Current /t REG_DWORD /d 1 /f
  reg save "HKCU\Software\TelagemTest" internal\winfs\reghive\testdata\sample.hve /y
  reg delete "HKCU\Software\TelagemTest" /f
  ```

  La raíz del hive guardado es `TelagemTest`, por lo que `OpenKey("Select")`
  navega a su subclave y `Value("Current")` devuelve el REG_DWORD.

  Para el forense real, el mismo parser se usa sobre hives `SYSTEM` y
  `Amcache.hve` copiados desde un snapshot VSS.
