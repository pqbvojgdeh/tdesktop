# Telegram Desktop MTProto patches

Эта ветка содержит последовательную серию патчей для актуальной ветки
`telegramdesktop/tdesktop:dev`. Основные направления: профили TLS ClientHello,
устойчивое подключение через MTProto FakeTLS-прокси, проверка и автоматическое
переключение прокси, расширенные настройки и связанный с ними интерфейс.

Порядок применения зафиксирован в [`patches/series.txt`](patches/series.txt).

| № | Патч | Назначение |
|---:|---|---|
| 1 | [`0001`](patches/0001-proxy-settings-and-data-model.diff) | Добавляет модель расширенных настроек прокси и необходимые поля `ProxyData`: ClientHello, slow-connect, IPv6 и автопереключение. |
| 2 | [`0002`](patches/0002-chromium-synthetic-resumption-cache.diff) | Добавляет ограниченный по времени кэш синтетического Chromium TLS resumption. |
| 3 | [`0003`](patches/0003-client-hello-validation.diff) | Добавляет структурную проверку сформированного TLS ClientHello и его расширений. |
| 4 | [`0004`](patches/0004-client-hello-profiles-and-slow-scheduler.diff) | Реализует профили Chrome, Firefox, Safari, Yandex и Chromium, а также планировщик задержанных подключений. |
| 5 | [`0005`](patches/0005-mtproto-profile-test-entrypoint-test-build-only.diff) | Добавляет build-only точку входа для запуска встроенных тестов ClientHello. |
| 6 | [`0006`](patches/0006-proxy-check-coordinator-and-rotation.diff) | Добавляет общий координатор проверок прокси и базовый механизм автоматической ротации. |
| 7 | [`0007`](patches/0007-proxy-address-priority-and-resolution.diff) | Добавляет выбор приоритета IPv4/IPv6 и применяет его при разрешении адресов прокси. |
| 8 | [`0008`](patches/0008-proxy-ui-style.diff) | Добавляет стили для расширенного интерфейса настроек прокси. |
| 9 | [`0009`](patches/0009-proxy-ui-implementation.diff) | Реализует расширенный UI: профили ClientHello, slow-connect, проверки и ротацию прокси. |
| 10 | [`0010`](patches/0010-proxy-ui-model.diff) | Расширяет модель и контроллер списка прокси для нового интерфейса. |
| 11 | [`0011`](patches/0011-proxy-resolved-ip-health-and-timeouts.diff) | Добавляет учёт состояния разрешённых IP, карантин неудачных адресов и таймауты подключения. |
| 12 | [`0012`](patches/0012-main-menu-version-commit-build-tooltip.diff) | Показывает в главном меню версию, commit и сведения о сборке. |
| 13 | [`0013`](patches/0013-settings-versioning-slow-policy-and-resumption-terminology.diff) | Версионирует расширение настроек, выносит slow-connect policy и уточняет lifecycle Chromium resumption. |
| 14 | [`0014`](patches/0014-proxy-check-instance-lifetime.diff) | Защищает проверки прокси от уничтожения связанного MTProto `Instance`. |
| 15 | [`0015`](patches/0015-resolved-ip-round-robin-and-quarantine.diff) | Добавляет round-robin разрешённых IP и корректный переход между адресами с учётом карантина. |
| 16 | [`0016`](patches/0016-proxy-ui-global-and-offline-configuration.diff) | Делает глобальные параметры доступными при отключённом прокси и убирает лишнее постоянное обновление UI. |
| 17 | [`0017`](patches/0017-resolved-ip-failure-classification-and-backoff.diff) | Классифицирует ошибки resolved IP и переносит ожидание карантина в управляемый backoff. |
| 18 | [`0018`](patches/0018-slow-connect-overflow-and-slot-hardening.diff) | Защищает slow-connect scheduler от переполнений, потери слотов и TCP-burst. |
| 19 | [`0019`](patches/0019-proxy-settings-length-prefixed-extension.diff) | Переводит расширение настроек на length-prefixed формат версии 2 с безопасным пропуском неизвестных данных. |
| 20 | [`0020`](patches/0020-proxy-check-threading-and-adaptive-autoswitch.diff) | Фиксирует thread-affinity координатора и добавляет адаптивный алгоритм автопереключения. |
| 21 | [`0021`](patches/0021-production-policy-tests-and-clienthello-stress.diff) | Добавляет production-policy тесты и усиленный stress-test генерации ClientHello. |
| 22 | [`0022`](patches/0022-test-harness-and-settings-deserialization-hardening.diff) | Усиливает тестовый harness и обработку повреждённых или несовместимых расширений настроек. |
| 23 | [`0023`](patches/0023-ui-localization-and-clienthello-validation-hardening.diff) | Локализует новый UI, усиливает проверку ClientHello и отображение build metadata. |
| 24 | [`0024`](patches/0024-clienthello-selection-and-profile-lifecycle-hardening.diff) | Делает случайный профиль стабильным в рамках сессии и уточняет lifecycle профилей и resumption. |
| 25 | [`0025`](patches/0025-faketls-classification-and-build-metadata-hardening.diff) | Унифицирует распознавание FakeTLS и безопасно встраивает commit/build/Qt metadata. |
| 26 | [`0026`](patches/0026-proxy-rotation-scoring-and-timeout-budget-hardening.diff) | Оценивает прокси по сглаженному ping, разбросу, отказам и свежести; ограничивает общий timeout budget. |
| 27 | [`0027`](patches/0027-proxy-check-lifecycle-and-ui-localization-hardening.diff) | Защищает batch-проверки от синхронных callbacks, сохраняет порядок строк и исправляет локализацию/доступность UI. |

Серия автоматически проверяется workflow
[`Validate MTProto patch series`](.github/workflows/validate-patch-series.yml):
патчи применяются к текущему `dev`, затем выполняются проверки контрактов и
компилируются отдельные C++20 policy-тесты.
