angular.module("hit-settings", [ "common" ]), angular.module("commonServices", []), 
angular.module("common", [ "ngResource", "default", "xml", "hl7v2-edi", "hl7v2", "edi", "soap", "hit-util" ]), 
angular.module("main", [ "common" ]), angular.module("account", [ "common" ]), angular.module("cf", [ "common" ]), 
angular.module("doc", [ "common" ]), angular.module("cb", [ "common" ]), angular.module("hit-tool-directives", []), 
angular.module("hit-tool-services", [ "common" ]), angular.module("documentation", []), 
angular.module("domains", []), angular.module("logs", [ "common" ]), angular.module("transport", []), 
angular.module("reports", [ "common", "treeGrid" ]), angular.module("cache", []);

var app = angular.module("hit-app", [ "ngRoute", "ui.bootstrap", "ngCookies", "LocalStorageModule", "treeGrid", "ngResource", "ngSanitize", "ngIdle", "ngAnimate", "ui.bootstrap", "ui-notification", "angularBootstrapNavTree", "QuickList", "hit-util", "format", "default", "hl7v2-edi", "xml", "hl7v2", "edi", "soap", "cf", "cb", "reports", "ngTreetable", "hit-tool-directives", "hit-tool-services", "commonServices", "smart-table", "hit-profile-viewer", "hit-validation-result", "hit-vocab-search", "hit-report-viewer", "hit-testcase-details", "hit-testcase-tree", "hit-settings", "doc", "account", "main", "hit-manual-report-viewer", "ociFixedHeader", "ngFileUpload", "ui.tree", "ui.select", "hit-edit-testcase-details", "angularFileUpload", "documentation", "domains", "logs", "transport", "angular-cache", "cache", "ngFileSaver", "LocalForageModule" ]), httpHeaders, loginMessage, spinner, mToHide = [ "usernameNotFound", "emailNotFound", "usernameFound", "emailFound", "loginSuccess", "userAdded", "uploadImageFailed" ], msg = {};

app.config(function($routeProvider, $httpProvider, localStorageServiceProvider, KeepaliveProvider, IdleProvider, NotificationProvider, $provide) {
    localStorageServiceProvider.setPrefix("hit-app").setStorageType("sessionStorage"), 
    $routeProvider.when("/", {
        templateUrl: "views/home.html"
    }).when("/home", {
        templateUrl: "views/home.html"
    }).when("/doc", {
        templateUrl: "views/documentation/documentation.html"
    }).when("/setting", {
        templateUrl: "views/setting.html"
    }).when("/about", {
        templateUrl: "views/about.html"
    }).when("/profilevalidation", {
        templateUrl: "views/profilevalidation.html",
        controller: "UploadCtrl",
        resolve: {
            isValidationOnly: function() {
                return !0;
            }
        }
    }).when("/cf", {
        templateUrl: "views/cf/cf.html"
    }).when("/cb", {
        templateUrl: "views/cb/cb.html"
    }).when("/error", {
        templateUrl: "error.html"
    }).when("/transport", {
        templateUrl: "views/transport/transport.html"
    }).when("/forgotten", {
        templateUrl: "views/account/forgotten.html",
        controller: "ForgottenCtrl"
    }).when("/registration", {
        templateUrl: "views/account/registration.html",
        controller: "RegistrationCtrl"
    }).when("/useraccount", {
        templateUrl: "views/account/userAccount.html"
    }).when("/glossary", {
        templateUrl: "views/glossary.html"
    }).when("/resetPassword", {
        templateUrl: "views/account/registerResetPassword.html",
        controller: "RegisterResetPasswordCtrl",
        resolve: {
            isFirstSetup: function() {
                return !1;
            }
        }
    }).when("/registrationSubmitted", {
        templateUrl: "views/account/registrationSubmitted.html"
    }).when("/uploadTokens", {
        templateUrl: "views/home.html",
        controller: "UploadTokenCheckCtrl"
    }).when("/addprofiles", {
        redirectTo: "/cf"
    }).when("/saveCBTokens", {
        templateUrl: "views/home.html",
        controller: "UploadCBTokenCheckCtrl"
    }).when("/addcbprofiles", {
        templateUrl: "views/home.html",
        controller: "UploadCBTokenCheckCtrl"
    }).when("/domains", {
        templateUrl: "views/domains/domains.html"
    }).when("/logs", {
        templateUrl: "views/logs/logs.html"
    }).when("/reports", {
        templateUrl: "views/reports/reports.html"
    }).otherwise({
        redirectTo: "/"
    }), $httpProvider.interceptors.push("interceptor1"), $httpProvider.interceptors.push("interceptor2"), 
    $httpProvider.interceptors.push("interceptor3"), $httpProvider.interceptors.push("interceptor4"), 
    IdleProvider.idle(7200), IdleProvider.timeout(30), KeepaliveProvider.interval(3), 
    NotificationProvider.setOptions({
        delay: 3e4,
        maxCount: 1
    }), httpHeaders = $httpProvider.defaults.headers, $provide.decorator("nvFileOverDirective", [ "$delegate", function($delegate) {
        var directive = $delegate[0], link = directive.link;
        return directive.compile = function() {
            return function(scope, element, attrs) {
                var overClass = attrs.overClass || "nv-file-over";
                link.apply(this, arguments), element.on("dragleave", function() {
                    element.removeClass(overClass);
                });
            };
        }, $delegate;
    } ]);
}), app.factory("interceptor1", function($q, $rootScope, $location, StorageService, $window) {
    var handle = function(response) {
        440 === response.status ? (response.data = "Session timeout", $rootScope.openSessionExpiredDlg()) : 498 === response.status && (response.data = "Invalid Application State", 
        $rootScope.openVersionChangeDlg());
    };
    return {
        responseError: function(response) {
            return handle(response), $q.reject(response);
        }
    };
}), app.factory("interceptor2", function($q, $rootScope, $location, StorageService, $window) {
    return {
        response: function(response) {
            return response || $q.when(response);
        },
        responseError: function(response) {
            if (401 === response.status && "api/accounts/cuser" !== response.config.url) {
                if ("api/accounts/login" !== response.config.url) {
                    var deferred = $q.defer(), req = {
                        config: response.config,
                        deferred: deferred
                    };
                    $rootScope.requests401.push(req);
                }
                return $rootScope.$broadcast("event:loginRequired"), $q.when(response);
            }
            return $q.reject(response);
        }
    };
}), app.factory("interceptor3", function($q, $rootScope, $location, StorageService, $window) {
    return {
        response: function(response) {
            return spinner = !1, response || $q.when(response);
        },
        responseError: function(response) {
            return spinner = !1, $q.reject(response);
        }
    };
}), app.factory("interceptor4", function($q, $rootScope, $location, StorageService, $window) {
    var setMessage = function(response) {
        if (response.data && response.data.text && response.data.type) if (401 === response.status) loginMessage = {
            text: response.data.text,
            type: response.data.type,
            skip: response.data.skip,
            show: !0,
            manualHandle: response.data.manualHandle
        }; else if (503 === response.status) msg = {
            text: "server.down",
            type: "danger",
            show: !0,
            manualHandle: !0
        }; else {
            msg = {
                text: response.data.text,
                type: response.data.type,
                skip: response.data.skip,
                show: !0,
                manualHandle: response.data.manualHandle
            };
            for (var found = !1, i = 0; i < mToHide.length && !found; ) msg.text === mToHide[i] && (found = !0), 
            i++;
            found === !0 && (msg.show = !1);
        }
    };
    return {
        response: function(response) {
            return setMessage(response), response || $q.when(response);
        },
        responseError: function(response) {
            return setMessage(response), $q.reject(response);
        }
    };
}), app.run(function(Session, $rootScope, $location, $modal, TestingSettings, AppInfo, $q, $sce, $templateCache, $compile, StorageService, $window, $route, $timeout, $http, User, Idle, Transport, IdleService, userInfoService, base64, Notification, DomainsManager, $filter) {
    StorageService.set(StorageService.ACTIVE_SUB_TAB_KEY, null);
    var domainParam = $location.search().d ? decodeURIComponent($location.search().d) : null;
    $rootScope.appLoad = function(domainParam) {
        void 0 === domainParam && (domainParam = $location.search().d ? decodeURIComponent($location.search().d) : null), 
        AppInfo.get().then(function(appInfo) {
            $rootScope.loadingDomain = !0, $rootScope.appInfo = appInfo, $rootScope.apiLink = $rootScope.appInfo.url + $rootScope.appInfo.apiDocsPath, 
            httpHeaders.common.rsbVersion = appInfo.rsbVersion;
            var previousToken = StorageService.get(StorageService.APP_STATE_TOKEN);
            null != previousToken && previousToken !== appInfo.rsbVersion && $rootScope.openVersionChangeDlg(), 
            StorageService.set(StorageService.APP_STATE_TOKEN, appInfo.rsbVersion), void 0 != domainParam && null != domainParam && StorageService.set(StorageService.APP_SELECTED_DOMAIN, domainParam);
            var storedDomain = StorageService.get(StorageService.APP_SELECTED_DOMAIN), domainFound = null;
            $rootScope.domain = null, $rootScope.appInfo.selectedDomain = null, $rootScope.domainsByOwner = {
                my: [],
                others: []
            }, DomainsManager.getDomains().then(function(domains) {
                if ($rootScope.appInfo.domains = domains, null != $rootScope.appInfo.domains) {
                    if ($rootScope.initDomainsByOwner(), 1 === $rootScope.appInfo.domains.length) domainFound = $rootScope.appInfo.domains[0].domain; else if (null != storedDomain) {
                        $rootScope.appInfo.domains = $filter("orderBy")($rootScope.appInfo.domains, "position");
                        for (var i = 0; i < $rootScope.appInfo.domains.length; i++) if ($rootScope.appInfo.domains[i].domain === storedDomain) {
                            domainFound = $rootScope.appInfo.domains[i].domain;
                            break;
                        }
                    }
                    if (null == domainFound) {
                        for (var i = 0; i < $rootScope.appInfo.domains.length; i++) if ("default" === $rootScope.appInfo.domains[i].domain) {
                            domainFound = $rootScope.appInfo.domains[i].domain;
                            break;
                        }
                        null == domainFound && ($rootScope.appInfo.domains = $filter("orderBy")($rootScope.appInfo.domains, "position"), 
                        domainFound = $rootScope.appInfo.domains[0].domain);
                    }
                    $rootScope.clearDomainSession(), DomainsManager.getDomainByKey(domainFound).then(function(result) {
                        $rootScope.appInfo.selectedDomain = result.domain, StorageService.set(StorageService.APP_SELECTED_DOMAIN, result.domain), 
                        $rootScope.domain = result, $rootScope.loadingDomain = !1, $timeout(function() {
                            Transport.configs = {}, Transport.getDomainForms($rootScope.domain.domain).then(function(transportForms) {
                                $rootScope.transportSupported = null != transportForms && transportForms.length > 0, 
                                $rootScope.transportSupported && angular.forEach(transportForms, function(transportForm) {
                                    var protocol = transportForm.protocol;
                                    Transport.configs[protocol] || (Transport.configs[protocol] = {}), Transport.configs[protocol].forms || (Transport.configs[protocol].forms = {}), 
                                    Transport.configs[protocol].forms = transportForm, Transport.configs[protocol].error = null, 
                                    Transport.configs[protocol].description = transportForm.description, Transport.configs[protocol].key = transportForm.protocol, 
                                    Transport.getConfigData($rootScope.domain.domain, protocol).then(function(data) {
                                        Transport.configs[protocol].data = data, Transport.configs[protocol].open = {
                                            ta: !0,
                                            sut: !1
                                        };
                                    }, function(error) {
                                        Transport.configs[protocol].error = error.data;
                                    });
                                });
                            }, function(error) {
                                $scope.error = "No transport configs found.";
                            });
                        }, 500);
                    }, function(error) {
                        $rootScope.loadingDomain = !0, $rootScope.openUnknownDomainDlg();
                    });
                } else $rootScope.openCriticalErrorDlg("No Tool scope found. Please contact the administrator");
            }, function(error) {
                $rootScope.openCriticalErrorDlg("No Tool scope found. Please contact the administrator");
            });
        }, function(error) {
            $rootScope.loadingDomain = !0, $rootScope.appInfo = {}, $rootScope.openCriticalErrorDlg("Failed to fetch the server. Please try again");
        });
    }, $rootScope.appLoad(domainParam), $rootScope.appInfo = {}, $rootScope.stackPosition = 0, 
    $rootScope.transportSupported = !1, $rootScope.scrollbarWidth = null, $rootScope.vcModalInstance = null, 
    $rootScope.sessionExpiredModalInstance = null, $rootScope.errorModalInstanceInstance = null;
    var initUser = function(user) {
        userInfoService.setCurrentUser(user), User.initUser(user);
    };
    $rootScope.clearDomainSession = function() {
        StorageService.set(StorageService.CF_SELECTED_TESTPLAN_ID_KEY, null), StorageService.set(StorageService.CF_EDITOR_CONTENT_KEY, null), 
        StorageService.set(StorageService.CF_LOADED_TESTCASE_ID_KEY, null), StorageService.set(StorageService.CB_EDITOR_CONTENT_KEY, null), 
        StorageService.set(StorageService.CB_SELECTED_TESTCASE_TYPE_KEY, null), StorageService.set(StorageService.CB_LOADED_TESTCASE_ID_KEY, null), 
        StorageService.set(StorageService.CB_LOADED_TESTCASE_TYPE_KEY, null), StorageService.set(StorageService.CB_LOADED_TESTSTEP_TYPE_KEY, null), 
        StorageService.set(StorageService.CB_LOADED_TESTSTEP_ID_KEY, null), StorageService.set(StorageService.ISOLATED_EDITOR_CONTENT_KEY, null), 
        StorageService.set(StorageService.ISOLATED_SELECTED_TESTCASE_TYPE_KEY, null), StorageService.set(StorageService.CB_SELECTED_TESTPLAN_ID_KEY, null), 
        StorageService.set(StorageService.CB_SELECTED_TESTPLAN_TYPE_KEY, null), StorageService.set(StorageService.CB_SELECTED_TESTPLAN_SCOPE_KEY, null), 
        StorageService.set(StorageService.CF_SELECTED_TESTPLAN_SCOPE_KEY, null), StorageService.set(StorageService.CF_SELECTED_TESTPLAN_ID_KEY, null), 
        StorageService.set(StorageService.CF_SELECTED_TESTPLAN_TYPE_KEY, null), StorageService.set(StorageService.CB_MANAGE_SELECTED_TESTCASE_ID_KEY, null), 
        StorageService.set(StorageService.CB_MANAGE_SELECTED_TESTCASE_TYPE_KEY, null), StorageService.set(StorageService.CB_MANAGE_LOADED_TESTCASE_ID_KEY, null), 
        StorageService.set(StorageService.CB_MANAGE_LOADED_TESTCASE_TYPE_KEY, null), StorageService.set(StorageService.CB_MANAGE_LOADED_TESTSTEP_TYPE_KEY, null), 
        StorageService.set(StorageService.CB_MANAGE_LOADED_TESTSTEP_ID_KEY, null), StorageService.set(StorageService.CB_MANAGE_SELECTED_TESTPLAN_ID_KEY, null), 
        StorageService.set(StorageService.CB_MANAGE_SELECTED_TESTPLAN_TYPE_KEY, null), StorageService.set(StorageService.CB_MANAGE_SELECTED_TESTPLAN_SCOPE_KEY, null), 
        StorageService.set(StorageService.APP_SELECTED_DOMAIN, null), StorageService.set(StorageService.CB_TEST_PLANS, []), 
        StorageService.set(StorageService.CB_LOADED_TESTCASE_ID_KEY, null), StorageService.set(StorageService.ACTIVE_SUB_TAB_KEY, null), 
        StorageService.set(StorageService.TEST_STEP_EXECUTION_MESSAGES_KEY, null), StorageService.set(StorageService.TEST_STEP_VALIDATION_REPORTS_KEY, null), 
        StorageService.set(StorageService.TEST_STEP_MESSAGE_TREES_KEY, null), StorageService.set(StorageService.TEST_STEP_VALIDATION_RESULTS_KEY, null), 
        StorageService.set(StorageService.TEST_STEP_EXECUTION_STATUSES_KEY, null), StorageService.set(StorageService.CB_SELECTED_TESTCASE_ID_KEY, null), 
        StorageService.set(StorageService.TEST_CASE_EXECUTION_STATUSES_KEY, null), StorageService.set(StorageService.TEST_CASE_VALIDATION_RESULTS_KEY, null);
    }, $rootScope.selectDomain = function(domain) {
        null != domain && (StorageService.set(StorageService.APP_SELECTED_DOMAIN, domain), 
        $location.search("d", domain), $location.url("/home"), $rootScope.appLoad());
    }, $rootScope.setDomain = function(domain) {
        null != domain && $rootScope.domainsByOwner.my.includes(domain) && StorageService.set(StorageService.APP_SELECTED_DOMAIN, domain);
    }, $rootScope.reloadPage = function() {
        $window.location.reload();
    }, $rootScope.$watch(function() {
        return $location.path();
    }, function(newLocation, oldLocation) {
        if ($rootScope.activePath === newLocation) {
            var back, historyState = $window.history.state;
            back = !!(historyState && historyState.position <= $rootScope.stackPosition), back ? $rootScope.stackPosition-- : $rootScope.stackPosition++;
        } else $route.current && ($window.history.replaceState({
            position: $rootScope.stackPosition
        }, ""), $rootScope.stackPosition++);
    }), $rootScope.isActive = function(path) {
        return path === $rootScope.activePath;
    }, $rootScope.setActive = function(path) {
        "" === path || "/" === path ? $location.path("/home") : $rootScope.activePath = path;
    }, $rootScope.isSubActive = function(path) {
        return path === $rootScope.subActivePath;
    }, $rootScope.setSubActive = function(path) {
        $rootScope.subActivePath = path, StorageService.set(StorageService.ACTIVE_SUB_TAB_KEY, path);
    }, $rootScope.msg = function() {
        return msg;
    }, $rootScope.loginMessage = function() {
        return loginMessage;
    }, $rootScope.showSpinner = function() {
        return spinner;
    }, $rootScope.createGuestIfNotExist = function() {
        User.createGuestIfNotExist().then(function(guest) {
            initUser(guest);
        }, function(error) {
            $rootScope.openCriticalErrorDlg("ERROR: Sorry, Failed to initialize the session. Please refresh the page and try again.");
        });
    }, $rootScope.requests401 = [], $rootScope.$on("event:loginRequired", function() {
        $rootScope.showLoginDialog();
    }), $rootScope.$on("event:loginConfirmed", function() {
        initUser(userInfoService.getCurrentUser());
        var i, requests = $rootScope.requests401, retry = function(req) {
            $http(req.config).then(function(response) {
                req.deferred.resolve(response);
            });
        };
        for (i = 0; i < requests.length; i += 1) retry(requests[i]);
        $rootScope.requests401 = [], $window.location.reload();
    }), $rootScope.$on("event:loginRequest", function(event, username, password) {
        httpHeaders.common.Accept = "application/json", httpHeaders.common.Authorization = "Basic " + base64.encode(username + ":" + password), 
        $http.get("api/accounts/login").success(function() {
            httpHeaders.common.Authorization = null, $http.get("api/accounts/cuser").then(function(result) {
                if (result.data && null != result.data) {
                    var rs = angular.fromJson(result.data);
                    userInfoService.setCurrentUser(rs), $rootScope.$broadcast("event:loginConfirmed");
                } else userInfoService.setCurrentUser(null);
            }, function() {
                userInfoService.setCurrentUser(null);
            });
        });
    }), $rootScope.$on("event:loginRequestWithAuth", function(event, auth, path, loadApp) {
        httpHeaders.common.Accept = "application/json", httpHeaders.common.Authorization = "Basic " + auth, 
        $http.get("api/accounts/login").success(function() {
            httpHeaders.common.Authorization = null, $http.get("api/accounts/cuser").then(function(result) {
                if (result.data && null != result.data) {
                    var rs = angular.fromJson(result.data);
                    initUser(rs), void 0 !== path ? (loadApp && $rootScope.appLoad(), $location.url(path)) : (loadApp && $rootScope.appLoad(), 
                    $rootScope.$broadcast("event:loginConfirmed"));
                } else userInfoService.setCurrentUser(null);
            }, function() {
                userInfoService.setCurrentUser(null);
            });
        });
    }), $rootScope.$on("event:loginRedirectRequest", function(event, username, password, path) {
        httpHeaders.common.Accept = "application/json", httpHeaders.common.Authorization = "Basic " + base64.encode(username + ":" + password), 
        $http.get("api/accounts/login").success(function() {
            httpHeaders.common.Authorization = null, $http.get("api/accounts/cuser").then(function(result) {
                if (result.data && null != result.data) {
                    var rs = angular.fromJson(result.data);
                    initUser(rs), $rootScope.$broadcast("event:loginConfirmed");
                } else userInfoService.setCurrentUser(null);
                $location.url(path);
            }, function() {
                userInfoService.setCurrentUser(null);
            });
        });
    }), $rootScope.$on("event:logoutRequest", function() {
        httpHeaders.common.Authorization = null, userInfoService.setCurrentUser(null), $http.get("j_spring_security_logout").then(function(result) {
            $rootScope.createGuestIfNotExist(), $rootScope.$broadcast("event:logoutConfirmed");
        });
    }), $rootScope.$on("event:loginCancel", function() {
        httpHeaders.common.Authorization = null;
    }), $rootScope.$on("$routeChangeStart", function(next, current) {
        msg && "false" === msg.manualHandle && (msg.show = !1);
    }), $rootScope.$watch(function() {
        return $rootScope.msg().text;
    }, function(value) {
        $rootScope.showNotification($rootScope.msg());
    }), $rootScope.$watch("language()", function(value) {
        $rootScope.showNotification($rootScope.msg());
    }), $rootScope.loadFromCookie = function() {
        userInfoService.hasCookieInfo() === !0 && (userInfoService.loadFromCookie(), httpHeaders.common.Authorization = userInfoService.getHthd());
    }, $rootScope.showNotification = function(m) {
        if (void 0 != m && m.show && null != m.text) {
            var msg = angular.copy(m), message = $.i18n.prop(msg.text), type = msg.type;
            "danger" === type ? Notification.error({
                message: message,
                templateUrl: "NotificationErrorTemplate.html",
                scope: $rootScope,
                delay: 1e4
            }) : "warning" === type ? Notification.warning({
                message: message,
                templateUrl: "NotificationWarningTemplate.html",
                scope: $rootScope,
                delay: 5e3
            }) : "success" === type && Notification.success({
                message: message,
                templateUrl: "NotificationSuccessTemplate.html",
                scope: $rootScope,
                delay: 5e3
            }), m.text = null, m.type = null, m.show = !1;
        }
    }, $rootScope.getScrollbarWidth = function() {
        if (0 == $rootScope.scrollbarWidth) {
            var outer = document.createElement("div");
            outer.style.visibility = "hidden", outer.style.width = "100px", outer.style.msOverflowStyle = "scrollbar", 
            document.body.appendChild(outer);
            var widthNoScroll = outer.offsetWidth;
            outer.style.overflow = "scroll";
            var inner = document.createElement("div");
            inner.style.width = "100%", outer.appendChild(inner);
            var widthWithScroll = inner.offsetWidth;
            outer.parentNode.removeChild(outer), $rootScope.scrollbarWidth = widthNoScroll - widthWithScroll;
        }
        return $rootScope.scrollbarWidth;
    }, userInfoService.loadFromServer().then(function(currentUser) {
        null !== currentUser && null != currentUser.accountId && void 0 != currentUser.accountId ? initUser(currentUser) : $rootScope.createGuestIfNotExist();
    }, function(error) {
        $rootScope.createGuestIfNotExist();
    }), $rootScope.getAppInfo = function() {
        return $rootScope.appInfo;
    }, $rootScope.isAuthenticationRequired = function() {
        return $rootScope.getAppInfo().options && "true" === $rootScope.getAppInfo().options.AUTHENTICATION_REQUIRED;
    }, $rootScope.isEmployerRequired = function() {
        return $rootScope.getAppInfo().options && "true" === $rootScope.getAppInfo().options.EMPLOYER_REQUIRED;
    }, $rootScope.isCbManagementSupported = function() {
        return $rootScope.getAppInfo().options && "true" === $rootScope.getAppInfo().options.CB_MANAGEMENT_SUPPORTED;
    }, $rootScope.isCfManagementSupported = function() {
        return $rootScope.getAppInfo().options && "true" === $rootScope.getAppInfo().options.CF_MANAGEMENT_SUPPORTED;
    }, $rootScope.isDocumentationManagementSupported = function() {
        return $rootScope.getAppInfo().options && "true" === $rootScope.getAppInfo().options.DOC_MANAGEMENT_SUPPORTED;
    }, $rootScope.isDomainOwner = function(email) {
        return null != $rootScope.domain && null != $rootScope.domain.ownerEmails && $rootScope.domain.ownerEmails.length() > 0 && $rootScope.domain.ownerEmails.indexOf(email) != -1;
    }, $rootScope.isDomainOwner = function() {
        return null != $rootScope.domain && $rootScope.domain.owner === userInfoService.getUsername();
    }, $rootScope.isDomainsManagementSupported = function() {
        return $rootScope.getAppInfo().options && "true" === $rootScope.getAppInfo().options.DOMAIN_MANAGEMENT_SUPPORTED || userInfoService.isAdmin() || userInfoService.isSupervisor() || userInfoService.isDeployer();
    }, $rootScope.isLoggedIn = function() {
        return userInfoService.isAuthenticated();
    }, $rootScope.isDomainSelectionSupported = function() {
        return $rootScope.getAppInfo().options && "true" === $rootScope.getAppInfo().options.DOMAIN_SELECTION_SUPPORTED;
    }, $rootScope.isUserLoginSupported = function() {
        return $rootScope.getAppInfo().options && "true" === $rootScope.getAppInfo().options.USER_LOGIN_SUPPORTED;
    }, $rootScope.isReportSavingSupported = function() {
        return $rootScope.domain && $rootScope.domain.options && "true" === $rootScope.domain.options.REPORT_SAVING_SUPPORTED;
    }, $rootScope.isToolScopeSelectionDisplayed = function() {
        return $rootScope.getAppInfo().options && "true" === $rootScope.getAppInfo().options.TOOL_SCOPE_SELECTON_DISPLAYED;
    }, $rootScope.isUserLoginSupported = function() {
        return $rootScope.getAppInfo().options && "true" === $rootScope.getAppInfo().options.USER_LOGIN_SUPPORTED;
    }, $rootScope.isDevTool = function() {
        return $rootScope.getAppInfo().options && "true" === $rootScope.getAppInfo().options.IS_DEV_TOOL;
    }, $rootScope.getAppURL = function() {
        return $rootScope.appInfo.url;
    };
}), angular.module("ui.bootstrap.carousel", [ "ui.bootstrap.transition" ]).controller("CarouselController", [ "$scope", "$timeout", "$transition", "$q", function($scope, $timeout, $transition, $q) {} ]).directive("carousel", [ function() {
    return {};
} ]), angular.module("hit-tool-services").factory("TabSettings", [ "$rootScope", function($rootScope) {
    return {
        new: function(key) {
            return {
                key: key,
                activeTab: 0,
                getActiveTab: function() {
                    return this.activeTab;
                },
                setActiveTab: function(value) {
                    this.activeTab = value, this.save();
                },
                save: function() {
                    sessionStorage.setItem(this.key, this.activeTab);
                },
                restore: function() {
                    this.activeTab = null != sessionStorage.getItem(this.key) && "" != sessionStorage.getItem(this.key) ? parseInt(sessionStorage.getItem(this.key)) : 0;
                }
            };
        }
    };
} ]), app.controller("ErrorDetailsCtrl", function($scope, $modalInstance, error) {
    $scope.error = error, $scope.ok = function() {
        $modalInstance.close($scope.error);
    }, $scope.cancel = function() {
        $modalInstance.dismiss("cancel");
    };
}), app.directive("stRatio", function() {
    return {
        link: function(scope, element, attr) {
            var ratio = +attr.stRatio;
            element.css("width", ratio + "%");
        }
    };
}), app.controller("TableFoundCtrl", function($scope, $modalInstance, table) {
    $scope.table = table, $scope.tmpTableElements = [].concat(null != table ? table.valueSetElements : []), 
    $scope.cancel = function() {
        $modalInstance.dismiss("cancel");
    };
}), app.controller("ValidationResultInfoCtrl", [ "$scope", "$modalInstance", function($scope, $modalInstance) {
    $scope.close = function() {
        $modalInstance.dismiss("cancel");
    };
} ]), app.filter("capitalize", function() {
    return function(input) {
        return input ? input.charAt(0).toUpperCase() + input.substr(1).toLowerCase() : "";
    };
}), app.controller("ErrorCtrl", [ "$scope", "$modalInstance", "StorageService", "$window", function($scope, $modalInstance, StorageService, $window) {
    $scope.refresh = function() {
        $modalInstance.close($window.location.reload());
    };
} ]), app.controller("FailureCtrl", [ "$scope", "$modalInstance", "StorageService", "$window", "error", function($scope, $modalInstance, StorageService, $window, error) {
    $scope.error = error, $scope.close = function() {
        $modalInstance.close();
    };
} ]), app.service("base64", function() {
    var keyStr = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
    this.encode = function(input) {
        for (var chr1, chr2, enc1, enc2, enc3, output = "", chr3 = "", enc4 = "", i = 0; i < input.length; ) chr1 = input.charCodeAt(i++), 
        chr2 = input.charCodeAt(i++), chr3 = input.charCodeAt(i++), enc1 = chr1 >> 2, enc2 = (3 & chr1) << 4 | chr2 >> 4, 
        enc3 = (15 & chr2) << 2 | chr3 >> 6, enc4 = 63 & chr3, isNaN(chr2) ? enc3 = enc4 = 64 : isNaN(chr3) && (enc4 = 64), 
        output = output + keyStr.charAt(enc1) + keyStr.charAt(enc2) + keyStr.charAt(enc3) + keyStr.charAt(enc4), 
        chr1 = chr2 = chr3 = "", enc1 = enc2 = enc3 = enc4 = "";
        return output;
    }, this.decode = function(input) {
        var chr1, chr2, enc1, enc2, enc3, output = "", chr3 = "", enc4 = "", i = 0;
        for (input = input.replace(/[^A-Za-z0-9\+\/\=]/g, ""); i < input.length; ) enc1 = keyStr.indexOf(input.charAt(i++)), 
        enc2 = keyStr.indexOf(input.charAt(i++)), enc3 = keyStr.indexOf(input.charAt(i++)), 
        enc4 = keyStr.indexOf(input.charAt(i++)), chr1 = enc1 << 2 | enc2 >> 4, chr2 = (15 & enc2) << 4 | enc3 >> 2, 
        chr3 = (3 & enc3) << 6 | enc4, output += String.fromCharCode(chr1), 64 !== enc3 && (output += String.fromCharCode(chr2)), 
        64 !== enc4 && (output += String.fromCharCode(chr3)), chr1 = chr2 = chr3 = "", enc1 = enc2 = enc3 = enc4 = "";
    };
}), app.factory("i18n", function() {
    var language, setLanguage = function(theLanguage) {
        $.i18n.properties({
            name: "messages",
            path: "lang/",
            mode: "map",
            language: theLanguage,
            callback: function() {
                language = theLanguage;
            }
        });
    };
    return setLanguage("en"), {
        setLanguage: setLanguage
    };
}), app.factory("Resource", [ "$resource", function($resource) {
    return function(url, params, methods) {
        var defaults = {
            update: {
                method: "put",
                isArray: !1
            },
            create: {
                method: "post"
            }
        };
        methods = angular.extend(defaults, methods);
        var resource = $resource(url, params, methods);
        return resource.prototype.$save = function(successHandler, errorHandler) {
            return this.id ? this.$update(successHandler, errorHandler) : this.$create(successHandler, errorHandler);
        }, resource;
    };
} ]), angular.module("commonServices").factory("StorageService", [ "$rootScope", "localStorageService", function($rootScope, localStorageService) {
    var service = {
        CF_EDITOR_CONTENT_KEY: "CF_EDITOR_CONTENT",
        CF_LOADED_TESTCASE_ID_KEY: "CF_LOADED_TESTCASE_ID",
        CF_LOADED_TESTCASE_TYPE_KEY: "CF_LOADED_TESTCASE_TYPE",
        CB_EDITOR_CONTENT_KEY: "CB_EDITOR_CONTENT",
        CB_SELECTED_TESTCASE_ID_KEY: "CB_SELECTED_TESTCASE_ID",
        CB_SELECTED_TESTCASE_TYPE_KEY: "CB_SELECTED_TESTCASE_TYPE",
        CB_LOADED_TESTCASE_ID_KEY: "CB_LOADED_TESTCASE_ID",
        CB_LOADED_TESTCASE_TYPE_KEY: "CB_LOADED_TESTCASE_TYPE",
        CB_LOADED_TESTSTEP_TYPE_KEY: "CB_LOADED_TESTSTEP_TYPE_KEY",
        CB_LOADED_TESTSTEP_ID_KEY: "CB_LOADED_TESTSTEP_ID",
        TRANSPORT_CONFIG_KEY: "TRANSPORT_CONFIG_KEY",
        ACTIVE_SUB_TAB_KEY: "ACTIVE_SUB_TAB",
        CB_TESTCASE_LOADED_RESULT_MAP_KEY: "CB_TESTCASE_LOADED_RESULT_MAP_KEY",
        SETTINGS_KEY: "SETTINGS_KEY",
        USER_KEY: "USER_KEY",
        USER_CONFIG_KEY: "USER_CONFIG_KEY",
        TRANSPORT_CONFIG_KEY: "TRANSPORT_CONFIG_KEY",
        APP_STATE_TOKEN: "APP_STATE_TOKEN",
        TRANSPORT_DISABLED: "TRANSPORT_DISABLED",
        TRANSPORT_PROTOCOL: "TRANSPORT_PROTOCOL",
        CB_SELECTED_TESTPLAN_ID_KEY: "CB_SELECTED_TESTPLAN_ID",
        CB_SELECTED_TESTPLAN_TYPE_KEY: "CB_SELECTED_TESTPLAN_TYPE",
        CB_SELECTED_TESTPLAN_SCOPE_KEY: "CB_SELECTED_TESTPLAN_SCOPE_KEY",
        CF_SELECTED_TESTPLAN_SCOPE_KEY: "CF_SELECTED_TESTPLAN_SCOPE_KEY",
        CF_SELECTED_TESTPLAN_ID_KEY: "CF_SELECTED_TESTPLAN_ID",
        CF_SELECTED_TESTPLAN_TYPE_KEY: "CF_SELECTED_TESTPLAN_TYPE",
        TRANSPORT_TIMEOUT: "TRANSPORT_TIMEOUT",
        CB_MANAGE_SELECTED_TESTCASE_ID_KEY: "CB_MANAGE_SELECTED_TESTCASE_ID",
        CB_MANAGE_SELECTED_TESTCASE_TYPE_KEY: "CB_MANAGE_SELECTED_TESTCASE_TYPE",
        CB_MANAGE_LOADED_TESTCASE_ID_KEY: "CB_MANAGE_LOADED_TESTCASE_ID",
        CB_MANAGE_LOADED_TESTCASE_TYPE_KEY: "CB_MANAGE_LOADED_TESTCASE_TYPE",
        CB_MANAGE_LOADED_TESTSTEP_TYPE_KEY: "CB_MANAGE_LOADED_TESTSTEP_TYPE_KEY",
        CB_MANAGE_LOADED_TESTSTEP_ID_KEY: "CB_MANAGE_LOADED_TESTSTEP_ID",
        CB_MANAGE_SELECTED_TESTPLAN_ID_KEY: "CB_MANAGE_SELECTED_TESTPLAN_ID",
        CB_MANAGE_SELECTED_TESTPLAN_TYPE_KEY: "CB_MANAGE_SELECTED_TESTPLAN_TYPE",
        CB_MANAGE_SELECTED_TESTPLAN_SCOPE_KEY: "CB_MANAGE_SELECTED_TESTPLAN_SCOPE_KEY",
        DOC_MANAGE_SELECTED_SCOPE_KEY: "DOC_MANAGE_SELECTED_SCOPE_KEY",
        APP_SELECTED_DOMAIN: "APP_SELECTED_DOMAIN",
        DOMAIN_MANAGE_SELECTED_SCOPE_KEY: "DOMAIN_MANAGE_SELECTED_SCOPE_KEY",
        DOMAIN_MANAGE_SELECTED_ID: "DOMAIN_MANAGE_SELECTED_ID",
        CF_MANAGE_SELECTED_TESTPLAN_ID_KEY: "CF_MANAGE_SELECTED_TESTPLAN_ID_KEY",
        CB_TEST_PLANS: "CB_TEST_PLANS",
        TEST_STEP_EXECUTION_MESSAGES_KEY: "testStepExecutionMessages",
        TEST_STEP_VALIDATION_REPORTS_KEY: "testStepValidationReports",
        TEST_STEP_MESSAGE_TREES_KEY: "testStepMessageTrees",
        TEST_STEP_VALIDATION_RESULTS_KEY: "testStepValidationResults",
        TEST_STEP_EXECUTION_STATUSES_KEY: "testStepExecutionStatuses",
        TEST_CASE_EXECUTION_STATUSES_KEY: "testCaseExecutionStatuses",
        TEST_CASE_VALIDATION_RESULTS_KEY: "testCaseValidationResults",
        remove: function(key) {
            return localStorageService.remove(key);
        },
        removeList: function(key1, key2, key3) {
            return localStorageService.remove(key1, key2, key3);
        },
        clearAll: function() {
            return localStorageService.clearAll();
        },
        set: function(key, val) {
            return localStorageService.set(key, val);
        },
        get: function(key) {
            return localStorageService.get(key);
        },
        getTransportConfig: function(domain, protocol) {
            return localStorageService.get(domain + "-" + protocol + "-transport-configs");
        },
        setTransportConfig: function(domain, protocol, val) {
            return localStorageService.set(domain + "-" + protocol + "-transport-configs", val);
        }
    };
    return service;
} ]), angular.module("transport").factory("Transport", function($q, $http, StorageService, User, $timeout, $rootScope) {
    var Transport = {
        running: !1,
        configs: {},
        transactions: [],
        logs: {},
        timeout: null != StorageService.get(StorageService.TRANSPORT_TIMEOUT) && void 0 != StorageService.get(StorageService.TRANSPORT_TIMEOUT) ? StorageService.get(StorageService.TRANSPORT_TIMEOUT) : 120,
        disabled: null == StorageService.get(StorageService.TRANSPORT_DISABLED) || StorageService.get(StorageService.TRANSPORT_DISABLED),
        setDisabled: function(disabled) {
            this.disabled = disabled;
        },
        setTimeout: function(timeout) {
            this.timeout = timeout, StorageService.set(StorageService.TRANSPORT_TIMEOUT, timeout);
        },
        getTimeout: function() {
            return this.timeout;
        },
        getDomainForms: function(domain) {
            var delay = $q.defer();
            return $http.get("api/transport/forms/" + domain).then(function(response) {
                var data = angular.fromJson(response.data);
                delay.resolve(data);
            }, function(response) {
                delay.reject(response);
            }), delay.promise;
        },
        getConfigData: function(domain, protocol) {
            var delay = $q.defer();
            return null != domain && null != protocol && User.info && null != User.info && null != User.info.id ? $http.post("api/transport/" + domain + "/" + protocol + "/configs").then(function(response) {
                delay.resolve(angular.fromJson(response.data));
            }, function(response) {
                delay.reject(response);
            }) : delay.reject("Domain, protocol or user info not provided"), delay.promise;
        },
        searchTransaction: function(testStepId, config, responseMessageId, domain, protocol) {
            var delay = $q.defer(), self = this;
            if (null != config) {
                var data = angular.fromJson({
                    testStepId: testStepId,
                    userId: User.info.id,
                    config: config,
                    responseMessageId: responseMessageId
                });
                $http.post("api/transport/" + domain + "/" + protocol + "/searchTransaction", data).then(function(response) {
                    null != response.data && "" != response.data ? self.transactions[testStepId] = angular.fromJson(response.data) : self.transactions[testStepId] = null, 
                    delay.resolve(self.transactions[testStepId]);
                }, function(response) {
                    self.transactions[testStepId] = null, delay.reject(self.transactions[testStepId]);
                });
            } else delay.reject("Configuration info not found");
            return delay.promise;
        },
        deleteTransaction: function(testStepId) {
            var delay = $q.defer(), self = this;
            if (self.transactions && null != self.transactions && self.transactions[testStepId]) {
                var transaction = self.transactions[testStepId];
                $http.post("api/transport/transaction/" + transaction.id + "/delete").then(function(response) {
                    delete self.transactions[testStepId], delay.resolve(!0);
                }, function(response) {
                    delete self.transactions[testStepId], delay.resolve(!0);
                });
            } else delay.resolve(!0);
            return delay.promise;
        },
        stopListener: function(testStepId, domain, protocol) {
            var self = this, delay = $q.defer();
            return this.deleteTransaction(testStepId).then(function(result) {
                var data = angular.fromJson({
                    testStepId: testStepId
                });
                $http.post("api/transport/" + domain + "/" + protocol + "/stopListener", data).then(function(response) {
                    self.running = !0, delay.resolve(!0);
                }, function(response) {
                    self.running = !1, delay.reject(null);
                });
            }), delay.promise;
        },
        startListener: function(testStepId, responseMessageId, domain, protocol) {
            var delay = $q.defer(), self = this;
            return this.deleteTransaction(testStepId).then(function(result) {
                var data = angular.fromJson({
                    testStepId: testStepId,
                    responseMessageId: responseMessageId
                });
                $http.post("api/transport/" + domain + "/" + protocol + "/startListener", data).then(function(response) {
                    self.running = !0, delay.resolve(!0);
                }, function(response) {
                    self.running = !1, delay.reject(null);
                });
            }), delay.promise;
        },
        send: function(testStepId, message, domain, protocol) {
            var delay = $q.defer(), self = this;
            return this.deleteTransaction(testStepId).then(function(result) {
                var data = angular.fromJson({
                    testStepId: testStepId,
                    message: message,
                    config: self.configs[protocol].data.taInitiator
                });
                $http.post("api/transport/" + domain + "/" + protocol + "/send", data).then(function(response) {
                    self.transactions[testStepId] = angular.fromJson(response.data), delay.resolve(self.transactions[testStepId]);
                }, function(response) {
                    self.transactions[testStepId] = null, delay.reject(response);
                });
            }), delay.promise;
        },
        populateMessage: function(testStepId, message, domain, protocol) {
            var delay = $q.defer(), data = angular.fromJson({
                testStepId: testStepId,
                message: message
            });
            return $http.post("api/transport/" + domain + "/" + protocol + "/populateMessage", data).then(function(response) {
                delay.resolve(angular.fromJson(response.data));
            }, function(response) {
                delay.reject(null);
            }), delay.promise;
        },
        saveTransportLog: function(testStepId, content, domain, protocol) {
            var delay = $q.defer(), data = angular.fromJson({
                testStepId: testStepId,
                content: content,
                domain: domain,
                protocol: protocol
            });
            return $http.post("api/logs/transport", data).then(function(response) {
                delay.resolve(response.data);
            }, function(response) {
                delay.reject(null);
            }), delay.promise;
        }
    };
    return Transport;
}), angular.module("cf").factory("CF", [ "$rootScope", "$http", "$q", "Message", "Tree", function($rootScope, $http, $q, Message, Tree) {
    var CF = {
        editor: null,
        cursor: null,
        tree: new Tree(),
        testCase: null,
        selectedTestCase: null,
        message: new Message(),
        searchTableId: 0,
        savedReports: [],
        selectedSavedReport: null
    };
    return CF;
} ]), angular.module("cf").factory("CFTestPlanExecutioner", [ "$q", "$http", "$rootScope", "CacheFactory", "$localForage", function($q, $http, $rootScope, CacheFactory, $localForage) {
    var manager = {
        getTestPlan: function(id) {
            var delay = $q.defer();
            return $http.get("api/cf/testplans/" + id + "/updateDate", {
                timeout: 18e4
            }).then(function(date) {
                $localForage.getItem("api/cf/testplans/" + id, !0).then(function(data) {
                    var cacheData = data;
                    cacheData && cacheData.updateDate === date.data ? delay.resolve(data) : $http.get("api/cf/testplans/" + id, {
                        timeout: 18e4
                    }).then(function(object) {
                        $localForage.setItem("api/cf/testplans/" + id, angular.fromJson(object.data)).then(function() {}), 
                        delay.resolve(angular.fromJson(object.data));
                    }, function(response) {
                        delay.reject(response.data);
                    });
                }, function(error) {
                    $http.get("api/cf/testplans/" + id, {
                        timeout: 18e4
                    }).then(function(object) {
                        $localForage.setItem("api/cf/testplans/" + id, angular.fromJson(object.data)).then(function() {}), 
                        delay.resolve(angular.fromJson(object.data));
                    }, function(response) {
                        delay.reject(response.data);
                    });
                });
            }, function(error) {
                $http.get("api/cf/testplans/" + id, {
                    timeout: 18e4
                }).then(function(object) {
                    $localForage.setItem("api/cf/testplans/" + id, angular.fromJson(object.data)).then(function() {}), 
                    delay.resolve(angular.fromJson(object.data));
                }, function(response) {
                    delay.reject(response.data);
                });
            }), delay.promise;
        },
        getTestPlans: function(scope, domain) {
            var delay = $q.defer();
            return $http.get("api/cf/testplans", {
                timeout: 18e4,
                params: {
                    scope: scope,
                    domain: domain
                }
            }).then(function(object) {
                delay.resolve(angular.fromJson(object.data));
            }, function(response) {
                delay.reject(response.data);
            }), delay.promise;
        }
    };
    return manager;
} ]), angular.module("cf").factory("CFTestPlanManager", [ "$q", "$http", function($q, $http) {
    var manager = {
        getTestStepGroupProfiles: function(groupId) {
            var delay = $q.defer();
            return $http.get("api/cf/management/testStepGroups/" + groupId + "/profiles", {
                timeout: 18e4
            }).then(function(object) {
                delay.resolve(angular.fromJson(object.data));
            }, function(response) {
                delay.reject(response.data);
            }), delay.promise;
        },
        getTestPlanProfiles: function(groupId) {
            var delay = $q.defer();
            return $http.get("api/cf/management/testPlans/" + groupId + "/profiles", {
                timeout: 18e4
            }).then(function(object) {
                delay.resolve(angular.fromJson(object.data));
            }, function(response) {
                delay.reject(response.data);
            }), delay.promise;
        },
        getTokenProfiles: function(format, token) {
            var delay = $q.defer();
            return $http.get("api/cf/" + format + "/management/tokens/" + token + "/profiles", {
                timeout: 18e4
            }).then(function(object) {
                delay.resolve(angular.fromJson(object.data));
            }, function(response) {
                delay.reject(response.data);
            }), delay.promise;
        },
        getTestPlan: function(id) {
            var delay = $q.defer();
            return $http.get("api/cf/management/testPlans/" + id, {
                timeout: 18e4
            }).then(function(object) {
                delay.resolve(angular.fromJson(object.data));
            }, function(response) {
                delay.reject(response.data);
            }), delay.promise;
        },
        getTestPlans: function(scope, domain) {
            var delay = $q.defer();
            return $http.get("api/cf/management/testPlans", {
                timeout: 18e4,
                params: {
                    scope: scope,
                    domain: domain
                }
            }).then(function(object) {
                delay.resolve(angular.fromJson(object.data));
            }, function(response) {
                delay.reject(response.data);
            }), delay.promise;
        },
        addChild: function(newGroup, parent) {
            var delay = $q.defer(), params = $.param({
                position: newGroup.position,
                name: newGroup.name,
                description: newGroup.description,
                scope: newGroup.scope,
                domain: newGroup.domain
            }), config = {
                headers: {
                    "Content-Type": "application/x-www-form-urlencoded;charset=utf-8;"
                }
            }, url = null;
            return url = "TestPlan" == parent.type ? "api/cf/management/testPlans/" + parent.id + "/addChild" : "api/cf/management/testStepGroups/" + parent.id + "/addChild", 
            $http.post(url, params, config).then(function(object) {
                delay.resolve(angular.fromJson(object.data));
            }, function(response) {
                delay.reject(response.data);
            }), delay.promise;
        },
        createTestPlan: function(testPlan) {
            var delay = $q.defer(), params = $.param({
                name: testPlan.name,
                description: testPlan.description,
                position: testPlan.position,
                domain: testPlan.domain,
                scope: testPlan.scope
            }), config = {
                headers: {
                    "Content-Type": "application/x-www-form-urlencoded;charset=utf-8;"
                }
            };
            return $http.post("api/cf/management/testPlans/create", params, config).then(function(object) {
                delay.resolve(angular.fromJson(object.data));
            }, function(response) {
                delay.reject(response.data);
            }), delay.promise;
        },
        deleteProfile: function(domain, profileId) {
            var delay = $q.defer();
            return $http.post("api/cf/" + domain + "/management/profiles/" + profileId + "/delete").then(function(object) {
                delay.resolve(angular.fromJson(object.data));
            }, function(response) {
                delay.reject(response.data);
            }), delay.promise;
        },
        deleteTestStepGroup: function(testStepGroup) {
            var delay = $q.defer(), context = "TestPlan" === testStepGroup.parent.type ? "testPlans/" : "testStepGroups/";
            return $http.post("api/cf/management/" + context + testStepGroup.parent.id + "/testStepGroups/" + testStepGroup.id + "/delete").then(function(object) {
                delay.resolve(angular.fromJson(object.data));
            }, function(response) {
                delay.reject(response.data);
            }), delay.promise;
        },
        deleteTestPlan: function(testPlan) {
            var delay = $q.defer();
            return $http.post("api/cf/management/testPlans/" + testPlan.id + "/delete").then(function(object) {
                delay.resolve(angular.fromJson(object.data));
            }, function(response) {
                delay.reject(response.data);
            }), delay.promise;
        },
        updateLocation: function(destination, child, newPosition) {
            var params = $.param({
                newPosition: newPosition,
                oldParentId: child.parent.id,
                oldParentType: child.parent.type,
                newParentId: destination.id,
                newParentType: destination.type
            }), config = {
                headers: {
                    "Content-Type": "application/x-www-form-urlencoded;charset=utf-8;"
                }
            }, delay = $q.defer();
            return $http.post("api/cf/management/testStepGroups/" + child.id + "/location", params, config).then(function(object) {
                delay.resolve(angular.fromJson(object.data));
            }, function(response) {
                delay.reject(response.data);
            }), delay.promise;
        },
        deleteToken: function(tok) {
            var delay = $q.defer();
            return $http.post("api/cf/management/tokens/" + tok + "/delete").then(function(object) {
                delay.resolve(angular.fromJson(object.data));
            }, function(error) {
                delay.reject(response.data);
            }), delay.promise;
        },
        saveTestStepGroup: function(format, scope, token, updated, removed, added, metadata) {
            var delay = $q.defer();
            return $http.post("api/cf/" + format + "/management/testStepGroups/" + metadata.groupId, {
                groupId: metadata.groupId,
                testcasename: metadata.name,
                testcasedescription: metadata.description,
                added: added,
                removed: removed,
                updated: updated,
                token: token,
                scope: scope
            }).then(function(object) {
                delay.resolve(angular.fromJson(object.data));
            }, function(response) {
                delay.reject(response.data);
            }), delay.promise;
        },
        saveTestPlan: function(format, scope, token, updated, removed, added, metadata) {
            var delay = $q.defer();
            return $http.post("api/cf/" + format + "/management/testPlans/" + metadata.groupId, {
                groupId: metadata.groupId,
                testcasename: metadata.name,
                testcasedescription: metadata.description,
                added: added,
                removed: removed,
                updated: updated,
                token: token,
                scope: scope
            }).then(function(object) {
                delay.resolve(angular.fromJson(object.data));
            }, function(response) {
                delay.reject(response.data);
            }), delay.promise;
        },
        publishTestPlan: function(groupId) {
            var delay = $q.defer();
            return $http.post("api/cf/management/testPlans/" + groupId + "/publish").then(function(object) {
                delay.resolve(angular.fromJson(object.data));
            }, function(response) {
                delay.reject(response.data);
            }), delay.promise;
        },
        unPublishTestPlan: function(groupId) {
            var delay = $q.defer();
            return $http.post("api/cf/management/testPlans/" + groupId + "/unPublish").then(function(object) {
                delay.resolve(angular.fromJson(object.data));
            }, function(response) {
                delay.reject(response.data);
            }), delay.promise;
        }
    };
    return manager;
} ]), angular.module("cf").service("modalService", [ "$modal", function($modal) {
    var modalDefaults = {
        backdrop: !0,
        keyboard: !0,
        modalFade: !0,
        templateUrl: "views/cf/modal.html"
    }, modalOptions = {
        closeButtonText: "Close",
        actionButtonText: "OK",
        headerText: "Proceed?",
        bodyText: "Perform this action?"
    };
    this.showModal = function(customModalDefaults, customModalOptions) {
        return customModalDefaults || (customModalDefaults = {}), customModalDefaults.backdrop = "static", 
        this.show(customModalDefaults, customModalOptions);
    }, this.show = function(customModalDefaults, customModalOptions) {
        var tempModalDefaults = {}, tempModalOptions = {};
        return angular.extend(tempModalDefaults, modalDefaults, customModalDefaults), angular.extend(tempModalOptions, modalOptions, customModalOptions), 
        tempModalDefaults.controller || (tempModalDefaults.controller = [ "$scope", "$modalInstance", function($scope, $modalInstance) {
            $scope.modalOptions = tempModalOptions, $scope.modalOptions.ok = function(result) {
                $modalInstance.close(result);
            }, $scope.modalOptions.close = function(result) {
                $modalInstance.dismiss("cancel");
            };
        } ]), $modal.open(tempModalDefaults).result;
    };
} ]), angular.module("cb").factory("CB", [ "Message", "ValidationSettings", "Tree", "StorageService", "Transport", "Logger", "User", function(Message, ValidationSettings, Tree, StorageService, Transport, Logger, User) {
    var CB = {
        testCase: null,
        selectedTestCase: null,
        selectedTestPlan: null,
        editor: null,
        tree: new Tree(),
        cursor: null,
        message: new Message(),
        logger: new Logger(),
        validationSettings: new ValidationSettings(),
        setContent: function(value) {
            CB.message.content = value, CB.editor.instance.doc.setValue(value), CB.message.notifyChange();
        },
        getContent: function() {
            return CB.message.content;
        },
        savedReports: [],
        selectedSavedReport: null
    };
    return CB;
} ]), angular.module("cb").factory("CBTestPlanListLoader", [ "$q", "$http", "StorageService", function($q, $http, StorageService) {
    return function(scope, domain) {
        var delay = $q.defer();
        return $http.get("api/cb/testplans", {
            timeout: 18e4,
            params: {
                scope: scope,
                domain: domain
            }
        }).then(function(object) {
            delay.resolve(angular.fromJson(object.data));
        }, function(response) {
            delay.reject(response.data);
        }), delay.promise;
    };
} ]), angular.module("cb").factory("CBTestPlanLoader", [ "$q", "$http", "$rootScope", "CacheFactory", "$localForage", function($q, $http, $rootScope, CacheFactory, $localForage) {
    return function(id, domain) {
        var delay = $q.defer();
        return $http.get("api/cb/testplans/" + id + "/updateDate", {
            timeout: 18e4
        }).then(function(date) {
            $localForage.getItem("api/cb/testplans/" + id, !0).then(function(data) {
                var cacheData = data;
                cacheData && cacheData.updateDate === date.data ? delay.resolve(data) : $http.get("api/cb/testplans/" + id, {
                    timeout: 18e4
                }).then(function(object) {
                    $localForage.setItem("api/cb/testplans/" + id, angular.fromJson(object.data)).then(function() {}), 
                    delay.resolve(angular.fromJson(object.data));
                }, function(response) {
                    delay.reject(response.data);
                });
            }, function(error) {
                $http.get("api/cb/testplans/" + id, {
                    timeout: 18e4
                }).then(function(object) {
                    $localForage.setItem("api/cb/testplans/" + id, angular.fromJson(object.data)).then(function() {}), 
                    delay.resolve(angular.fromJson(object.data));
                }, function(response) {
                    delay.reject(response.data);
                });
            });
        }, function(error) {
            $http.get("api/cb/testplans/" + id, {
                timeout: 18e4
            }).then(function(object) {
                $localForage.setItem("api/cb/testplans/" + id, angular.fromJson(object.data)).then(function() {}), 
                delay.resolve(angular.fromJson(object.data));
            }, function(response) {
                delay.reject(response.data);
            });
        }), delay.promise;
    };
} ]), angular.module("cb").factory("CBTestPlanManager", [ "$q", "$http", function($q, $http) {
    var manager = {
        getTestPlan: function(testPlanId) {
            var delay = $q.defer();
            return $http.get("api/cb/management/testPlans/" + testPlanId, {
                timeout: 18e4
            }).then(function(object) {
                delay.resolve(angular.fromJson(object.data));
            }, function(response) {
                delay.reject(response.data);
            }), delay.promise;
        },
        getTestPlans: function(scope, domain) {
            var delay = $q.defer();
            return $http.get("api/cb/management/testPlans", {
                timeout: 18e4,
                params: {
                    scope: scope,
                    domain: domain
                }
            }).then(function(object) {
                delay.resolve(angular.fromJson(object.data));
            }, function(response) {
                delay.reject(response.data);
            }), delay.promise;
        },
        publishTestPlan: function(testPlanId) {
            var delay = $q.defer();
            return $http.post("api/cb/management/testPlans/" + testPlanId + "/publish").then(function(object) {
                delay.resolve(angular.fromJson(object.data));
            }, function(response) {
                delay.reject(response.data);
            }), delay.promise;
        },
        deleteTestStep: function(testStep) {
            var delay = $q.defer();
            return $http.post("api/cb/management/testCases/" + testStep.parent.id + "/testSteps/" + testStep.id + "/delete").then(function(object) {
                delay.resolve(angular.fromJson(object.data));
            }, function(response) {
                delay.reject(response.data);
            }), delay.promise;
        },
        deleteTestCase: function(testCase) {
            var delay = $q.defer(), context = "TestPlan" === testCase.parent.type ? "testPlans/" : "testCaseGroups/";
            return $http.post("api/cb/management/" + context + testCase.parent.id + "/testCases/" + testCase.id + "/delete").then(function(object) {
                delay.resolve(angular.fromJson(object.data));
            }, function(response) {
                delay.reject(response.data);
            }), delay.promise;
        },
        deleteTestPlan: function(testPlan) {
            var delay = $q.defer();
            return $http.post("api/cb/management/testPlans/" + testPlan.id + "/delete").then(function(object) {
                delay.resolve(angular.fromJson(object.data));
            }, function(response) {
                delay.reject(response.data);
            }), delay.promise;
        },
        deleteTestCaseGroup: function(testCaseGroup) {
            var delay = $q.defer(), context = "TestPlan" === testCaseGroup.parent.type ? "testPlans/" : "testCaseGroups/";
            return $http.post("api/cb/management/" + context + testCaseGroup.parent.id + "/testCaseGroups/" + testCaseGroup.id + "/delete").then(function(object) {
                delay.resolve(angular.fromJson(object.data));
            }, function(response) {
                delay.reject(response.data);
            }), delay.promise;
        },
        updateTestCaseGroupName: function(node) {
            var delay = $q.defer();
            return $http.post("api/cb/management/testCaseGroups/" + node.id + "/name", {
                name: node.editName
            }).then(function(object) {
                delay.resolve(angular.fromJson(object.data));
            }, function(response) {
                delay.reject(response.data);
            }), delay.promise;
        },
        updateTestCaseName: function(node) {
            var delay = $q.defer();
            return $http.post("api/cb/management/testCases/" + node.id + "/name", {
                name: node.editName
            }).then(function(object) {
                delay.resolve(angular.fromJson(object.data));
            }, function(response) {
                delay.reject(response.data);
            }), delay.promise;
        },
        updateTestStepName: function(node) {
            var delay = $q.defer();
            return $http.post("api/cb/management/testSteps/" + node.id + "/name", {
                name: node.editName
            }).then(function(object) {
                delay.resolve(angular.fromJson(object.data));
            }, function(response) {
                delay.reject(response.data);
            }), delay.promise;
        },
        updateTestPlanName: function(node) {
            var delay = $q.defer();
            return $http.post("api/cb/management/testPlans/" + node.id + "/name", {
                name: node.editName
            }).then(function(object) {
                delay.resolve(angular.fromJson(object.data));
            }, function(response) {
                delay.reject(response.data);
            }), delay.promise;
        },
        saveZip: function(token, domain) {
            var delay = $q.defer();
            return $http.post("api/cb/management/saveZip/", {
                token: token,
                domain: domain
            }).then(function(object) {
                delay.resolve(angular.fromJson(object.data));
            }, function(response) {
                delay.reject(response.data);
            }), delay.promise;
        },
        unpublishTestPlan: function(testPlanId) {
            var delay = $q.defer();
            return $http.post("api/cb/management/testPlans/" + testPlanId + "/unpublish").then(function(object) {
                delay.resolve(angular.fromJson(object.data));
            }, function(response) {
                delay.reject(response.data);
            }), delay.promise;
        }
    };
    return manager;
} ]), angular.module("main").controller("MainService", function($scope) {}), angular.module("main").factory("TestingSettings", [ "$rootScope", function($rootScope) {
    var service = {
        activeTab: 0,
        getActiveTab: function() {
            return service.activeTab;
        },
        setActiveTab: function(value) {
            service.activeTab = value, service.save();
        },
        save: function() {
            sessionStorage.TestingActiveTab = service.activeTab;
        },
        restore: function() {
            service.activeTab = null != sessionStorage.TestingActiveTab && "" != sessionStorage.TestingActiveTab ? parseInt(sessionStorage.TestingActiveTab) : 0;
        }
    };
    return service;
} ]), angular.module("main").service("modalService", [ "$modal", function($modal) {
    var modalDefaults = {
        backdrop: !0,
        keyboard: !0,
        modalFade: !0,
        templateUrl: "views/modal.html"
    }, modalOptions = {
        closeButtonText: "Close",
        actionButtonText: "OK",
        headerText: "Proceed?",
        bodyText: "Perform this action?"
    };
    this.showModal = function(customModalDefaults, customModalOptions) {
        return customModalDefaults || (customModalDefaults = {}), customModalDefaults.backdrop = "static", 
        this.show(customModalDefaults, customModalOptions);
    }, this.show = function(customModalDefaults, customModalOptions) {
        var tempModalDefaults = {}, tempModalOptions = {};
        return angular.extend(tempModalDefaults, modalDefaults, customModalDefaults), angular.extend(tempModalOptions, modalOptions, customModalOptions), 
        tempModalDefaults.controller || (tempModalDefaults.controller = [ "$scope", "$modalInstance", function($scope, $modalInstance) {
            $scope.modalOptions = tempModalOptions, $scope.modalOptions.ok = function(result) {
                $modalInstance.close(result);
            }, $scope.modalOptions.close = function(result) {
                $modalInstance.dismiss("cancel");
            };
        } ]), $modal.open(tempModalDefaults).result;
    };
} ]), angular.module("account").factory("Account", function($http, $resource, $q) {
    var accountService = function() {};
    return accountService.disableAccount = function(id) {
        var delay = $q.defer();
        return $http.post("api/accounts/" + id + "/disable").then(function(object) {}, function(response) {
            console.log("error"), delay.reject(response.data);
        }), delay.promise;
    }, accountService.resource = function() {
        return $resource("api/accounts/:id", {
            id: "@id"
        });
    }, accountService;
}), angular.module("account").factory("LoginService", [ "$resource", "$q", function($resource, $q) {
    return function() {
        var myRes = $resource("api/accounts/login"), delay = $q.defer();
        return myRes.get({}, function(res) {
            delay.resolve(res);
        }), delay.promise;
    };
} ]), angular.module("account").factory("AccountLoader", [ "Account", "$q", function(Account, $q) {
    return function(acctID) {
        var delay = $q.defer();
        return Account.resource().get({
            id: acctID
        }, function(account) {
            delay.resolve(account);
        }, function() {
            delay.reject("Unable to fetch account");
        }), delay.promise;
    };
} ]), angular.module("account").factory("Testers", [ "$resource", function($resource) {
    return $resource("api/shortaccounts", {
        filter: [ "accountType::tester", "accountType::deployer", "accountType::admin" ]
    });
} ]), angular.module("account").factory("Supervisors", [ "$resource", function($resource) {
    return $resource("api/shortaccounts", {
        filter: "accountType::supervisor"
    });
} ]), angular.module("account").factory("MultiTestersLoader", [ "Testers", "$q", function(Testers, $q) {
    return function() {
        var delay = $q.defer();
        return Testers.query(function(auth) {
            delay.resolve(auth);
        }, function() {
            delay.reject("Unable to fetch list of testers");
        }), delay.promise;
    };
} ]), angular.module("account").factory("MultiSupervisorsLoader", [ "Supervisors", "$q", function(Supervisors, $q) {
    return function() {
        var delay = $q.defer();
        return Supervisors.query(function(res) {
            delay.resolve(res);
        }, function() {
            delay.reject("Unable to fetch list of supervisors");
        }), delay.promise;
    };
} ]), angular.module("account").factory("userLoaderService", [ "userInfo", "$q", function(userInfo, $q) {
    var load = function() {
        var delay = $q.defer();
        return userInfo.get({}, function(theUserInfo) {
            delay.resolve(theUserInfo);
        }, function() {
            delay.reject("Unable to fetch user info");
        }), delay.promise;
    };
    return {
        load: load
    };
} ]), angular.module("account").factory("userInfo", [ "$resource", function($resource) {
    return $resource("api/accounts/cuser");
} ]), angular.module("account").factory("userLoaderService", [ "userInfo", "$q", function(userInfo, $q) {
    var load = function() {
        var delay = $q.defer();
        return userInfo.get({}, function(theUserInfo) {
            delay.resolve(theUserInfo);
        }, function() {
            delay.reject("Unable to fetch user info");
        }), delay.promise;
    };
    return {
        load: load
    };
} ]), angular.module("account").factory("notificationService", function($http, $q) {
    var notificationService = function() {};
    return notificationService.saveNotification = function(notification) {
        var delay = $q.defer(), data = angular.fromJson(notification);
        return $http.post("api/notification/add", data).then(function(object) {
            var res = null != object.data && "" != object.data ? angular.fromJson(object.data) : null;
            delay.resolve(res);
        }, function(response) {
            console.log("error"), delay.reject(response.data);
        }), delay.promise;
    }, notificationService.updateNotification = function(notification) {
        var delay = $q.defer(), data = angular.fromJson(notification);
        return $http.post("api/notification/update", data).then(function(object) {
            var res = null != object.data && "" != object.data ? angular.fromJson(object.data) : null;
            delay.resolve(res);
        }, function(response) {
            console.log("error"), delay.reject(response.data);
        }), delay.promise;
    }, notificationService.getAllNotifications = function(notification) {
        var delay = $q.defer();
        return $http.get("api/notification/all").then(function(object) {
            var res = null != object.data && "" != object.data ? angular.fromJson(object.data) : null;
            delay.resolve(res);
        }, function(response) {
            delay.reject(response.data);
        }), delay.promise;
    }, notificationService;
}), angular.module("account").factory("userInfoService", [ "StorageService", "userLoaderService", "User", "Transport", "$q", "$timeout", "$rootScope", function(StorageService, userLoaderService, User, Transport, $q, $timeout, $rootScope) {
    var currentUser = null, supervisor = !1, tester = !1, publisher = !1, deployer = !1, admin = !1, id = null, username = "", fullName = "", lastTestPlanPersistenceId = null, employer = null, loadFromCookie = function() {
        id = StorageService.get("userID"), username = StorageService.get("username"), tester = StorageService.get("tester"), 
        supervisor = StorageService.get("supervisor"), deployer = StorageService.get("deployer"), 
        publisher = StorageService.get("publisher"), admin = StorageService.get("admin"), 
        lastTestPlanPersistenceId = StorageService.get("lastTestPlanPersistenceId"), employer = StorageService.get("employer");
    }, saveHthd = function(header) {
        StorageService.set("hthd", header);
    }, getHthd = function(header) {
        return StorageService.get("hthd");
    }, hasCookieInfo = function() {
        return "" !== StorageService.get("username");
    }, getAccountID = function() {
        return isAuthenticated() ? currentUser.accountId.toString() : "0";
    }, isAdmin = function() {
        return !admin && null != currentUser && null != $rootScope.appInfo.adminEmails && $rootScope.appInfo.adminEmails && (admin = Array.isArray($rootScope.appInfo.adminEmails) ? $rootScope.appInfo.adminEmails.indexOf(currentUser.email) >= 0 : $rootScope.appInfo.adminEmails === currentUser.email), 
        admin;
    }, isTester = function() {
        return tester;
    }, isSupervisor = function() {
        return supervisor;
    }, isDeployer = function() {
        return deployer;
    }, isPublisher = function() {
        return publisher;
    }, isPending = function() {
        return !(!isAuthenticated() || null == currentUser) && currentUser.pending;
    }, isAuthenticated = function() {
        var res = void 0 !== currentUser && null != currentUser && currentUser.authenticated === !0;
        return res;
    }, loadFromServer = function() {
        if (isAuthenticated()) {
            var delay = $q.defer();
            return $timeout(function() {
                delay.resolve(currentUser);
            }), delay.promise;
        }
        return userLoaderService.load();
    }, getCurrentUser = function() {
        return currentUser;
    }, setCurrentUser = function(newUser) {
        currentUser = newUser, null !== currentUser && void 0 !== currentUser ? (username = currentUser.username, 
        id = currentUser.accountId, fullName = currentUser.fullName, lastTestPlanPersistenceId = currentUser.lastTestPlanPersistenceId, 
        employer = currentUser.employer, angular.isArray(currentUser.authorities) && angular.forEach(currentUser.authorities, function(value, key) {
            switch (value.authority) {
              case "user":
                break;

              case "admin":
                admin = !0;
                break;

              case "tester":
                tester = !0;
                break;

              case "supervisor":
                supervisor = !0;
                break;

              case "deployer":
                deployer = !0;
                break;

              case "publisher":
                publisher = !0;
            }
        })) : (supervisor = !1, tester = !1, deployer = !1, publisher = !1, admin = !1, 
        username = "", id = null, fullName = "", lastTestPlanPersistenceId = null, employer = "");
    }, getUsername = function() {
        return username;
    }, getFullName = function() {
        return fullName;
    }, getLastTestPlanPersistenceId = function() {
        return lastTestPlanPersistenceId;
    }, getEmployer = function() {
        return employer;
    };
    return {
        saveHthd: saveHthd,
        getHthd: getHthd,
        hasCookieInfo: hasCookieInfo,
        loadFromCookie: loadFromCookie,
        getAccountID: getAccountID,
        isAdmin: isAdmin,
        isPublisher: isPublisher,
        isTester: isTester,
        isAuthenticated: isAuthenticated,
        isPending: isPending,
        isSupervisor: isSupervisor,
        isDeployer: isDeployer,
        setCurrentUser: setCurrentUser,
        getCurrentUser: getCurrentUser,
        loadFromServer: loadFromServer,
        getUsername: getUsername,
        getFullName: getFullName,
        getLastTestPlanPersistenceId: getLastTestPlanPersistenceId,
        getEmployer: getEmployer
    };
} ]), angular.module("doc").factory("DocumentationManager", [ "$q", "$http", function($q, $http) {
    var manager = {
        getInstallationGuide: function() {
            var delay = $q.defer();
            return $http.get("api/documentation/installationguides", {
                timeout: 6e4
            }).then(function(object) {
                null != object.data && "" != object.data ? delay.resolve(angular.fromJson(object.data)) : delay.resolve(null);
            }, function(response) {
                delay.reject(response.data);
            }), delay.promise;
        },
        getTestCaseDocuments: function(domain, scope) {
            var delay = $q.defer();
            return $http.get("api/documentation/testcases", {
                timeout: 6e4,
                params: {
                    domain: domain,
                    scope: scope
                }
            }).then(function(object) {
                null != object.data && "" != object.data ? delay.resolve(angular.fromJson(object.data)) : delay.resolve(null);
            }, function(response) {
                delay.reject(response.data);
            }), delay.promise;
        },
        getDocuments: function(domain, scope, type) {
            var delay = $q.defer();
            return $http.get("api/documentation/documents", {
                params: {
                    domain: domain,
                    scope: scope,
                    type: type
                }
            }).then(function(object) {
                delay.resolve(angular.fromJson(object.data));
            }, function(response) {
                delay.reject(response.data);
            }), delay.promise;
        },
        saveDocument: function(document) {
            var delay = $q.defer();
            return $http.post("api/documentation/documents", document).then(function(object) {
                delay.resolve(angular.fromJson(object.data));
            }, function(response) {
                delay.reject(response.data);
            }), delay.promise;
        },
        deleteDocument: function(id) {
            var delay = $q.defer();
            return $http.post("api/documentation/documents/" + id + "/delete").then(function(object) {
                delay.resolve(object.data);
            }, function(response) {
                delay.reject(response.data);
            }), delay.promise;
        },
        publishDocument: function(id) {
            var delay = $q.defer();
            return $http.post("api/documentation/documents/" + id + "/publish").then(function(object) {
                delay.resolve(object.data);
            }, function(response) {
                delay.reject(response.data);
            }), delay.promise;
        }
    };
    return manager;
} ]), angular.module("domains").factory("DomainsManager", [ "$q", "$http", function($q, $http) {
    var manager = {
        getUserDomains: function() {
            var delay = $q.defer();
            return $http.get("api/domains/findByUser", {
                timeout: 6e4
            }).then(function(object) {
                delay.resolve(angular.fromJson(object.data));
            }, function(response) {
                delay.reject(response.data);
            }), delay.promise;
        },
        findByUserAndRole: function() {
            var delay = $q.defer();
            return $http.get("api/domains/findByUserAndRole", {
                timeout: 6e4
            }).then(function(object) {
                delay.resolve(angular.fromJson(object.data));
            }, function(response) {
                delay.reject(response.data);
            }), delay.promise;
        },
        getDomains: function() {
            var delay = $q.defer();
            return $http.get("api/domains", {
                timeout: 6e4
            }).then(function(object) {
                delay.resolve(angular.fromJson(object.data));
            }, function(response) {
                delay.reject(response.data);
            }), delay.promise;
        },
        getDomainsByScope: function(scope) {
            var delay = $q.defer();
            return $http.get("api/domains/searchByScope" + {
                params: {
                    scope: scope
                }
            }).then(function(object) {
                delay.resolve(angular.fromJson(object.data));
            }, function(response) {
                delay.reject(response.data);
            }), delay.promise;
        },
        getDomainById: function(id) {
            var delay = $q.defer();
            return $http.get("api/domains/" + id, {
                timeout: 6e4
            }).then(function(object) {
                delay.resolve(angular.fromJson(object.data));
            }, function(response) {
                delay.reject(response.data);
            }), delay.promise;
        },
        canModify: function(id) {
            var delay = $q.defer();
            return $http.get("api/domains/" + id + "/canModify", {
                timeout: 6e4
            }).then(function(object) {
                delay.resolve(angular.fromJson(object.data));
            }, function(response) {
                delay.reject(response.data);
            }), delay.promise;
        },
        getUpdateDate: function(id) {
            var delay = $q.defer();
            return $http.get("api/domains/" + id + "/updateDate", {
                timeout: 6e4
            }).then(function(object) {
                delay.resolve(angular.fromJson(object.data));
            }, function(response) {
                delay.reject(response.data);
            }), delay.promise;
        },
        getDomainByKey: function(key) {
            var delay = $q.defer();
            return $http.get("api/domains/searchByKey", {
                params: {
                    key: key
                }
            }).then(function(object) {
                delay.resolve(angular.fromJson(object.data));
            }, function(response) {
                delay.reject(response.data);
            }), delay.promise;
        },
        save: function(domain) {
            var delay = $q.defer(), data = angular.fromJson(domain);
            return $http.post("api/domains/" + domain.id, data).then(function(object) {
                delay.resolve(angular.fromJson(object.data));
            }, function(response) {
                delay.reject(response.data);
            }), delay.promise;
        },
        publish: function(domainId) {
            var delay = $q.defer();
            return $http.post("api/domains/" + domainId + "/publish").then(function(object) {
                delay.resolve(angular.fromJson(object.data));
            }, function(response) {
                delay.reject(response.data);
            }), delay.promise;
        },
        unpublish: function(domainId) {
            var delay = $q.defer();
            return $http.post("api/domains/" + domainId + "/unpublish").then(function(object) {
                delay.resolve(angular.fromJson(object.data));
            }, function(response) {
                delay.reject(response.data);
            }), delay.promise;
        },
        saveAndPublish: function(domain) {
            var delay = $q.defer(), data = angular.fromJson(domain);
            return $http.post("api/domains/save-publish", data).then(function(object) {
                delay.resolve(angular.fromJson(object.data));
            }, function(response) {
                delay.reject(response.data);
            }), delay.promise;
        },
        saveAndUnpublish: function(domain) {
            var delay = $q.defer(), data = angular.fromJson(domain);
            return $http.post("api/domains/save-unpublish", data).then(function(object) {
                delay.resolve(angular.fromJson(object.data));
            }, function(response) {
                delay.reject(response.data);
            }), delay.promise;
        },
        delete: function(id) {
            var delay = $q.defer();
            return $http.post("api/domains/" + id + "/delete").then(function(object) {
                delay.resolve(angular.fromJson(object.data));
            }, function(response) {
                delay.reject(response.data);
            }), delay.promise;
        },
        create: function(name, key, scope, homeTitle) {
            var delay = $q.defer(), data = angular.fromJson({
                domain: key,
                name: name,
                scope: scope,
                homeTitle: homeTitle
            });
            return $http.post("api/domains/create", data).then(function(object) {
                delay.resolve(angular.fromJson(object.data));
            }, function(response) {
                delay.reject(response.data);
            }), delay.promise;
        },
        getDefaultHomeContent: function() {
            var delay = $q.defer();
            return $http.post("api/domains/home-content").then(function(object) {
                delay.resolve(angular.fromJson(object.data));
            }, function(response) {
                delay.reject(response.data);
            }), delay.promise;
        },
        getDefaultValueSetCopyright: function() {
            var delay = $q.defer();
            return $http.post("api/domains/valueset-copyright").then(function(object) {
                delay.resolve(angular.fromJson(object.data));
            }, function(response) {
                delay.reject(response.data);
            }), delay.promise;
        },
        getDefaultProfileInfo: function() {
            var delay = $q.defer();
            return $http.post("api/domains/profile-info").then(function(object) {
                delay.resolve(angular.fromJson(object.data));
            }, function(response) {
                delay.reject(response.data);
            }), delay.promise;
        },
        getDefaultMessageContent: function() {
            var delay = $q.defer();
            return $http.post("api/domains/message-content").then(function(object) {
                delay.resolve(angular.fromJson(object.data));
            }, function(response) {
                delay.reject(response.data);
            }), delay.promise;
        },
        getDefaultValidationResultInfo: function() {
            var delay = $q.defer();
            return $http.post("api/domains/validation-result-info").then(function(object) {
                delay.resolve(angular.fromJson(object.data));
            }, function(response) {
                delay.reject(response.data);
            }), delay.promise;
        }
    };
    return manager;
} ]), angular.module("logs").factory("ValidationLogService", [ "$q", "$http", function($q, $http) {
    var service = {
        getTotalCount: function(domain) {
            var delay = $q.defer();
            return $http.get("api/logs/validation/" + domain + "/count", {
                timeout: 18e4
            }).then(function(object) {
                delay.resolve(object.data);
            }, function(response) {
                delay.reject(response.data);
            }), delay.promise;
        },
        getAll: function(domain) {
            var delay = $q.defer();
            return $http.get("api/logs/validation/" + domain, {
                timeout: 18e4
            }).then(function(object) {
                delay.resolve(angular.fromJson(object.data));
            }, function(response) {
                delay.reject(response.data);
            }), delay.promise;
        },
        getById: function(logId) {
            var delay = $q.defer();
            return $http.get("api/logs/validation/" + logId, {
                timeout: 18e4
            }).then(function(object) {
                delay.resolve(angular.fromJson(object.data));
            }, function(response) {
                delay.reject(response.data);
            }), delay.promise;
        },
        deleteLog: function(logId) {
            var delay = $q.defer();
            return $http.post("api/logs/validation/" + logId + "/delete").then(function(object) {
                delay.resolve(angular.fromJson(object.data));
            }, function(response) {
                delay.reject(response.data);
            }), delay.promise;
        }
    };
    return service;
} ]), angular.module("logs").factory("TransportLogService", [ "$q", "$http", function($q, $http) {
    var service = {
        getTotalCount: function(domain) {
            var delay = $q.defer();
            return $http.get("api/logs/transport/" + domain + "/count", {
                timeout: 18e4
            }).then(function(object) {
                delay.resolve(object.data);
            }, function(response) {
                delay.reject(response.data);
            }), delay.promise;
        },
        getAll: function(domain) {
            var delay = $q.defer();
            return $http.get("api/logs/transport/" + domain, {
                timeout: 18e4
            }).then(function(object) {
                delay.resolve(angular.fromJson(object.data));
            }, function(response) {
                delay.reject(response.data);
            }), delay.promise;
        },
        getById: function(logId) {
            var delay = $q.defer();
            return $http.get("api/logs/transport/" + logId, {
                timeout: 18e4
            }).then(function(object) {
                delay.resolve(angular.fromJson(object.data));
            }, function(response) {
                delay.reject(response.data);
            }), delay.promise;
        },
        deleteLog: function(logId) {
            var delay = $q.defer();
            return $http.post("api/logs/transport/" + logId + "/delete").then(function(object) {
                delay.resolve(angular.fromJson(object.data));
            }, function(response) {
                delay.reject(response.data);
            }), delay.promise;
        }
    };
    return service;
} ]), angular.module("reports").factory("ReportService", [ "$rootScope", "$http", "$q", "$filter", "Notification", "FileSaver", function($rootScope, $http, $q, $filter, Notification, FileSaver) {
    var service = {
        downloadTestStepValidationReport: function(testStepValidationReportId, format) {
            var form = document.createElement("form");
            form.action = "api/tsReport/" + testStepValidationReportId + "/download", form.method = "POST", 
            form.target = "_target";
            var input = document.createElement("input");
            input.name = "format", input.value = format, form.appendChild(input), form.style.display = "none", 
            document.body.appendChild(form), form.submit();
        },
        downloadMessageValidationReport: function(testStepValidationReportId, format) {
            var form = document.createElement("form");
            form.action = "api/mReport" + testStepValidationReportId + "/download", form.method = "POST", 
            form.target = "_target";
            var input = document.createElement("input");
            input.name = "format", input.value = format, form.appendChild(input), form.style.display = "none", 
            document.body.appendChild(form), form.submit();
        },
        downloadTestCaseReports: function(testCaseId, format, result, comments, testPlanName, testGroupName) {
            var form = document.createElement("form");
            form.action = "api/tcReport/download", form.method = "POST", form.target = "_target";
            var input = document.createElement("input");
            input.name = "format", input.value = format, form.appendChild(input), input = document.createElement("input"), 
            input.name = "testCaseId", input.value = testCaseId, form.appendChild(input), input = document.createElement("input"), 
            input.name = "result", input.value = result, form.appendChild(input), input = document.createElement("input"), 
            input.name = "comments", input.value = comments, form.appendChild(input), input = document.createElement("input"), 
            input.name = "testPlan", input.value = testPlanName, form.appendChild(input), input = document.createElement("input"), 
            input.name = "testGroup", input.value = testGroupName, form.appendChild(input), 
            form.style.display = "none", document.body.appendChild(form), form.submit();
        },
        createMessageValidationReport: function(testStepId) {
            var delay = $q.defer(), data = angular.fromJson({
                testStepId: testStepId
            });
            return $http.post("api/tsReport/create", data).then(function(object) {
                var res = null != object.data && "" != object.data ? angular.fromJson(object.data) : null;
                delay.resolve(res);
            }, function(response) {
                delay.reject(response.data);
            }), delay.promise;
        },
        initTestStepValidationReport: function(testStepId) {
            var delay = $q.defer(), data = $.param({
                testStepId: testStepId
            }), config = {
                headers: {
                    "Content-Type": "application/x-www-form-urlencoded;charset=utf-8;"
                }
            };
            return $http.post("api/tsReport/init", data, config).then(function(object) {
                var res = null != object.data && "" != object.data ? angular.fromJson(object.data) : null;
                delay.resolve(res);
            }, function(response) {
                delay.reject(response.data);
            }), delay.promise;
        },
        getJson: function(testStepId, reportId) {
            var delay = $q.defer();
            return $http.get("api/tsReport/json", {
                params: {
                    testStepId: testStepId,
                    testReportId: reportId
                }
            }).then(function(response) {
                delay.resolve(response);
            }, function(error) {
                delay.reject(error.data);
            }), delay.promise;
        },
        updateTestStepValidationReport: function(testReportId, testStepId, result, comments) {
            var delay = $q.defer(), data = angular.fromJson({
                reportId: testReportId,
                testStepId: testStepId,
                result: result,
                comments: comments
            });
            return $http.post("api/tsReport/save", data).then(function(object) {
                var res = null != object.data && "" != object.data ? angular.fromJson(object.data) : null;
                delay.resolve(res);
            }, function(response) {
                delay.reject(response.data);
            }), delay.promise;
        },
        saveValidationReport: function(testStepValidationReportId) {
            var delay = $q.defer(), data = angular.fromJson({
                testStepValidationReportId: testStepValidationReportId
            });
            return $http.post("api/userTSReport/savePersistentUserTestStepReport", data).then(function(object) {
                var res = null != object.data && "" != object.data ? angular.fromJson(object.data) : null;
                delay.resolve(res);
            }, function(response) {
                console.log("error"), delay.reject(response.data);
            }), delay.promise;
        },
        saveTestCaseValidationReport: function(testCaseId, testStepReportIds, result, comments, testPlanName, testGroupName) {
            var delay = $q.defer(), data = angular.fromJson({
                testCaseId: testCaseId,
                testStepReportIds: testStepReportIds,
                result: result,
                comments: comments,
                testPlan: testPlanName,
                testGroup: testGroupName
            });
            return $http.post("api/userTCReport/savePersistentUserTestCaseReport", data).then(function(object) {
                var res = null != object.data && "" != object.data ? angular.fromJson(object.data) : null;
                delay.resolve(res);
            }, function(response) {
                delay.reject(response.data);
            }), delay.promise;
        },
        downloadUserTestStepValidationReport: function(testStepValidationReportId, format) {
            return $http.get("api/userTSReport/" + testStepValidationReportId + "/download/" + format, {
                responseType: "blob"
            }).then(function(response) {
                var filename, contentDisposition = response.headers("Content-Disposition");
                filename = null != contentDisposition ? contentDisposition.split(";")[1].split("filename")[1].split("=")[1].trim() : "report", 
                FileSaver.saveAs(response.data, filename);
            });
        },
        downloadUserTestCaseValidationReport: function(testStepValidationReportId, format) {
            return $http.get("api/userTCReport/" + testStepValidationReportId + "/download/" + format, {
                responseType: "blob"
            }).then(function(response) {
                var filename, contentDisposition = response.headers("Content-Disposition");
                filename = null != contentDisposition ? contentDisposition.split(";")[1].split("filename")[1].split("=")[1].trim() : "report", 
                FileSaver.saveAs(response.data, filename);
            });
        },
        getAllTSByAccountIdAndDomain: function(domain) {
            var delay = $q.defer();
            return $http.get("api/userTSReport/domain/" + domain, {
                timeout: 18e4
            }).then(function(object) {
                var res = null != object.data && "" != object.data ? angular.fromJson(object.data) : null;
                delay.resolve(res);
            }, function(response) {
                delay.reject(response.data);
            }), delay.promise;
        },
        getAllTSByAccountIdAndDomainAndtestStepId: function(domain, testStepId) {
            var delay = $q.defer();
            return $http.get("api/userTSReport/domain/" + domain + "/testStep/" + testStepId, {
                timeout: 18e4
            }).then(function(object) {
                var res = null != object.data && "" != object.data ? angular.fromJson(object.data) : null;
                delay.resolve(res);
            }, function(response) {
                delay.reject(response.data);
            }), delay.promise;
        },
        getAllIndependantTSByAccountIdAndDomainAndtestStepId: function(domain, testStepId) {
            var delay = $q.defer();
            return $http.get("api/userTSReport/domain/" + domain + "/testStep/" + testStepId, {
                timeout: 18e4,
                params: {
                    onlyIndependant: !0
                }
            }).then(function(object) {
                var res = null != object.data && "" != object.data ? angular.fromJson(object.data) : null;
                delay.resolve(res);
            }, function(response) {
                delay.reject(response.data);
            }), delay.promise;
        },
        getAllTCByAccountIdAndDomainAndtestCaseId: function(domain, testCaseId) {
            var delay = $q.defer();
            return $http.get("api/userTCReport/domain/" + domain + "/testCase/" + testCaseId, {
                timeout: 18e4
            }).then(function(object) {
                var res = null != object.data && "" != object.data ? angular.fromJson(object.data) : null;
                delay.resolve(res);
            }, function(response) {
                delay.reject(response.data);
            }), delay.promise;
        },
        getAllTCByAccountIdAndDomain: function(domain) {
            var delay = $q.defer();
            return $http.get("api/userTCReport/domain/" + domain, {
                timeout: 18e4
            }).then(function(object) {
                var res = null != object.data && "" != object.data ? angular.fromJson(object.data) : null;
                delay.resolve(res);
            }, function(response) {
                delay.reject(response.data);
            }), delay.promise;
        },
        getUserTSReport: function(id) {
            var delay = $q.defer();
            return $http.get("api/userTSReport/" + id, {
                timeout: 18e4
            }).then(function(object) {
                var res = null != object.data && "" != object.data ? angular.fromJson(object.data) : null;
                delay.resolve(res);
            }, function(response) {
                delay.reject(response.data);
            }), delay.promise;
        },
        getUserTSReportHTML: function(id) {
            var delay = $q.defer();
            return $http.get("api/userTSReport/" + id + "/html", {
                timeout: 18e4
            }).then(function(object) {
                var res = null != object.data && "" != object.data ? angular.fromJson(object.data) : null;
                delay.resolve(res);
            }, function(response) {
                delay.reject(response.data);
            }), delay.promise;
        },
        getUserTCReport: function(id) {
            var delay = $q.defer();
            return $http.get("api/userTCReport/" + id, {
                timeout: 18e4
            }).then(function(object) {
                var res = null != object.data && "" != object.data ? angular.fromJson(object.data) : null;
                delay.resolve(res);
            }, function(response) {
                delay.reject(response.data);
            }), delay.promise;
        },
        getUserTCReportHTML: function(id) {
            var delay = $q.defer();
            return $http.get("api/userTCReport/" + id + "/html", {
                timeout: 18e4
            }).then(function(object) {
                var res = null != object.data && "" != object.data ? angular.fromJson(object.data) : null;
                delay.resolve(res);
            }, function(response) {
                delay.reject(response.data);
            }), delay.promise;
        },
        getAllReportsByAccountIdAndDomain: function(domain) {
            var delay = $q.defer();
            return $http.get("api/reports/" + domain, {
                timeout: 18e4
            }).then(function(object) {
                var res = null != object.data && "" != object.data ? angular.fromJson(object.data) : null;
                delay.resolve(res);
            }, function(response) {
                delay.reject(response.data);
            }), delay.promise;
        },
        deleteTSReport: function(reportId) {
            var delay = $q.defer();
            return $http.post("api/userTSReport/" + reportId + "/deleteReport").then(function(object) {
                delay.resolve(angular.fromJson(object.data));
            }, function(response) {
                delay.reject(response.data);
            }), delay.promise;
        },
        deleteTCReport: function(reportId) {
            var delay = $q.defer();
            return $http.post("api/userTCReport/" + reportId + "/deleteReport").then(function(object) {
                delay.resolve(angular.fromJson(object.data));
            }, function(response) {
                delay.reject(response.data);
            }), delay.promise;
        }
    };
    return service;
} ]), angular.module("cache").factory("CachingService", [ "$q", "$http", "$rootScope", "CacheFactory", "CBTestPlanListLoader", "CBTestPlanLoader", "CFTestPlanExecutioner", function($q, $http, $rootScope, CacheFactory, CBTestPlanListLoader, CBTestPlanLoader, CFTestPlanExecutioner) {
    var manager = {
        cacheCBTestPlans: function(scope, domain) {
            var tcGlobalLoader = new CBTestPlanListLoader(scope, $rootScope.domain.domain);
            tcGlobalLoader.then(function(testPlans) {
                for (var i = 0; i < testPlans.length; i++) {
                    var tcLoader = new CBTestPlanLoader(testPlans[i].id, $rootScope.domain);
                    tcLoader.then(function(testPlan) {}, function(error) {});
                }
            }, function(error) {
                $scope.error = "Sorry, Cannot load the test plans. Please try again";
            });
        },
        cacheCFTestPlans: function(scope, domain) {
            CFTestPlanExecutioner.getTestPlans(scope, domain).then(function(testPlans) {
                for (var i = 0; i < testPlans.length; i++) CFTestPlanExecutioner.getTestPlan(testPlans[i].id, $rootScope.domain).then(function(testPlan) {}, function(error) {});
            }, function(error) {
                $scope.error = "Sorry, Cannot load the test plans. Please try again";
            });
        }
    };
    return manager;
} ]), angular.module("hit-settings").factory("SettingsService", [ "$q", "$http", "StorageService", function($q, $http, StorageService) {
    var options = null == StorageService.get(StorageService.SETTINGS_KEY) ? {
        validation: {
            show: {
                errors: !0,
                alerts: !0,
                warnings: !0,
                affirmatives: !1,
                informational: !1,
                specerrors: !0,
                ignores: !0
            }
        }
    } : angular.fromJson(StorageService.get(StorageService.SETTINGS_KEY)), settings = {
        options: options,
        set: function(options) {
            settings.options = options, StorageService.set(StorageService.SETTINGS_KEY, angular.toJson(options));
        },
        getValidationClassifications: function(domain) {
            var delay = $q.defer();
            return $http.get("api/hl7v2/validationconfig/" + domain.domain + "/getClassifications").then(function(object) {
                delay.resolve(angular.fromJson(object.data));
            }, function(response) {
                delay.reject(response.data);
            }), delay.promise;
        },
        saveValidationClassifications: function(classificationsData, domain) {
            var delay = $q.defer(), data = angular.fromJson(classificationsData);
            return $http.post("api/hl7v2/validationconfig/" + domain.domain + "/saveClassifications", data).then(function(object) {
                delay.resolve(angular.fromJson(object.data));
            }, function(response) {
                delay.reject(response.data);
            }), delay.promise;
        },
        resetClassifications: function(domain) {
            var delay = $q.defer();
            return $http.get("api/hl7v2/validationconfig/getDefaultClassifications").then(function(object) {
                delay.resolve(angular.fromJson(object.data));
            }, function(response) {
                delay.reject(response.data);
            }), delay.promise;
        }
    };
    return settings;
} ]), angular.module("main").controller("MainCtrl", function($scope, $rootScope, i18n, $location, userInfoService, $modal, $filter, base64, $http, Idle, Notification, IdleService, StorageService, TestingSettings, Session, AppInfo, User, $templateCache, $window, $sce, DomainsManager, Transport, $timeout, CBTestPlanListLoader, CBTestPlanLoader, CachingService, $localForage) {
    function closeModals() {
        $rootScope.warning && ($rootScope.warning.close(), $rootScope.warning = null), $rootScope.timedout && ($rootScope.timedout.close(), 
        $rootScope.timedout = null);
    }
    $rootScope.loginDialog = null, $rootScope.started = !1, $scope.notifications = [], 
    $scope.showNotificationPanel = !1;
    $location.search().d ? decodeURIComponent($location.search().d) : null;
    $scope.language = function() {
        return i18n.language;
    }, $scope.setLanguage = function(lang) {
        i18n.setLanguage(lang);
    }, $scope.activeWhen = function(value) {
        return value ? "active" : "";
    }, $scope.activeIfInList = function(value, pathsList) {
        var found = !1;
        if (angular.isArray(pathsList) === !1) return "";
        for (var i = 0; i < pathsList.length && found === !1; ) {
            if (pathsList[i] === value) return "active";
            i++;
        }
        return "";
    }, $scope.path = function() {
        return $location.url();
    }, $scope.login = function() {
        $scope.$emit("event:loginRequest", $scope.username, $scope.password);
    }, $scope.loginAndRedirect = function(path) {
        $scope.$emit("event:loginRedirectRequest", $scope.username, $scope.password, path);
    }, $scope.loginReq = function() {
        $rootScope.loginMessage() && ($rootScope.loginMessage().text = "", $rootScope.loginMessage().show = !1), 
        $scope.$emit("event:loginRequired");
    }, $scope.logout = function() {
        $scope.execLogout();
    }, $scope.execLogout = function() {
        userInfoService.setCurrentUser(null), $scope.username = $scope.password = null, 
        $scope.$emit("event:logoutRequest"), $window.location.href = "/gvt/#/home", $window.location.reload();
    }, $scope.cancel = function() {
        $scope.$emit("event:loginCancel");
    }, $scope.isAuthenticated = function() {
        return userInfoService.isAuthenticated();
    }, $scope.isPending = function() {
        return userInfoService.isPending();
    }, $scope.isSupervisor = function() {
        return userInfoService.isSupervisor();
    }, $scope.isTester = function() {
        return userInfoService.isTester();
    }, $scope.isAdmin = function() {
        return userInfoService.isAdmin();
    }, $scope.isPublisher = function() {
        return userInfoService.isPublisher();
    }, $scope.getRoleAsString = function() {
        return $scope.isTester() === !0 ? "tester" : $scope.isSupervisor() === !0 ? "Supervisor" : $scope.isAdmin() === !0 ? "Admin" : "undefined";
    }, $scope.getUsername = function() {
        return userInfoService.isAuthenticated() === !0 ? userInfoService.getUsername() : "";
    }, $rootScope.showLoginDialog = function(path) {
        $rootScope.loginDialog && null != $rootScope.loginDialog && $rootScope.loginDialog.opened && $rootScope.loginDialog.dismiss("cancel"), 
        $rootScope.loginDialog = $modal.open({
            backdrop: "static",
            keyboard: "false",
            controller: "LoginCtrl",
            size: "lg",
            templateUrl: "views/account/login.html",
            resolve: {
                user: function() {
                    return {
                        username: $scope.username,
                        password: $scope.password
                    };
                }
            }
        }), $rootScope.loginDialog.result.then(function(result) {
            result ? ($scope.username = result.username, $scope.password = result.password, 
            void 0 !== path ? $scope.loginAndRedirect(path + "&loggedin=true") : $scope.login()) : $scope.cancel();
        });
    }, $rootScope.started = !1, Idle.watch(), $rootScope.$on("IdleStart", function() {
        closeModals(), $rootScope.warning = $modal.open({
            templateUrl: "warning-dialog.html",
            windowClass: "modal-danger"
        });
    }), $rootScope.$on("IdleEnd", function() {
        closeModals();
    }), $rootScope.$on("IdleTimeout", function() {
        closeModals(), $scope.isAuthenticated() ? ($rootScope.$emit("event:execLogout"), 
        $rootScope.timedout = $modal.open({
            templateUrl: "timedout-dialog.html",
            windowClass: "modal-danger"
        })) : (StorageService.clearAll(), Session.delete().then(function(response) {
            $rootScope.timedout = $modal.open({
                templateUrl: "timedout-dialog.html",
                windowClass: "modal-danger",
                backdrop: !0,
                keyboard: "false",
                controller: "FailureCtrl",
                resolve: {
                    error: function() {
                        return "";
                    }
                }
            }), $rootScope.timedout.result.then(function() {
                $rootScope.clearTemplate(), $rootScope.reloadPage();
            }, function() {
                $rootScope.clearTemplate(), $rootScope.reloadPage();
            });
        }));
    }), $scope.addToHiddenList = function(id) {
        var hiddenIds;
        $localForage.getItem("hiddenNotifications", !0).then(function(hiddenIdsResults) {
            hiddenIds = hiddenIdsResults, hiddenIds.indexOf(id) === -1 && hiddenIds.push(id);
        }, function(error) {
            hiddenIds = [], hiddenIds[0] = id;
        }).finally(function() {
            $localForage.setItem("hiddenNotifications", hiddenIds).then(function(err) {
                $scope.updateNotifications($scope.rawNotifications);
            });
        });
    }, $scope.updateNotifications = function(result) {
        var filteredData = angular.copy(result);
        $localForage.getItem("hiddenNotifications", !0).then(function(hiddenIds) {
            null !== hiddenIds && (filteredData = filteredData.filter(function(noti) {
                return noti.dismissable === !1 || hiddenIds.indexOf(noti.id) === -1;
            }));
        }, function(error) {}).finally(function() {
            angular.equals(filteredData, $scope.notifications) || ($scope.notifications = angular.copy(filteredData)), 
            $scope.notifications.length > 0 ? $scope.showNotificationPanel = !0 : $scope.showNotificationPanel = !1;
        });
    }, $scope.$on("Keepalive", function() {
        IdleService.keepAlive().then(function(result) {
            $scope.rawNotifications = angular.copy(result), $scope.updateNotifications(result);
        });
    }), IdleService.keepAlive().then(function(result) {
        $scope.rawNotifications = angular.copy(result), $scope.updateNotifications(result);
    }), $rootScope.$on("event:execLogout", function() {
        $scope.execLogout();
    }), $rootScope.start = function() {
        closeModals(), Idle.watch(), $rootScope.started = !0;
    }, $rootScope.stop = function() {
        closeModals(), Idle.unwatch(), $rootScope.started = !1;
    }, $scope.checkForIE = function() {
        var BrowserDetect = {
            init: function() {
                this.browser = this.searchString(this.dataBrowser) || "An unknown browser", this.version = this.searchVersion(navigator.userAgent) || this.searchVersion(navigator.appVersion) || "an unknown version", 
                this.OS = this.searchString(this.dataOS) || "an unknown OS";
            },
            searchString: function(data) {
                for (var i = 0; i < data.length; i++) {
                    var dataString = data[i].string, dataProp = data[i].prop;
                    if (this.versionSearchString = data[i].versionSearch || data[i].identity, dataString) {
                        if (dataString.indexOf(data[i].subString) !== -1) return data[i].identity;
                    } else if (dataProp) return data[i].identity;
                }
            },
            searchVersion: function(dataString) {
                var index = dataString.indexOf(this.versionSearchString);
                if (index !== -1) return parseFloat(dataString.substring(index + this.versionSearchString.length + 1));
            },
            dataBrowser: [ {
                string: navigator.userAgent,
                subString: "Chrome",
                identity: "Chrome"
            }, {
                string: navigator.userAgent,
                subString: "OmniWeb",
                versionSearch: "OmniWeb/",
                identity: "OmniWeb"
            }, {
                string: navigator.vendor,
                subString: "Apple",
                identity: "Safari",
                versionSearch: "Version"
            }, {
                prop: window.opera,
                identity: "Opera",
                versionSearch: "Version"
            }, {
                string: navigator.vendor,
                subString: "iCab",
                identity: "iCab"
            }, {
                string: navigator.vendor,
                subString: "KDE",
                identity: "Konqueror"
            }, {
                string: navigator.userAgent,
                subString: "Firefox",
                identity: "Firefox"
            }, {
                string: navigator.vendor,
                subString: "Camino",
                identity: "Camino"
            }, {
                string: navigator.userAgent,
                subString: "Netscape",
                identity: "Netscape"
            }, {
                string: navigator.userAgent,
                subString: "MSIE",
                identity: "Explorer",
                versionSearch: "MSIE"
            }, {
                string: navigator.userAgent,
                subString: "Gecko",
                identity: "Mozilla",
                versionSearch: "rv"
            }, {
                string: navigator.userAgent,
                subString: "Mozilla",
                identity: "Netscape",
                versionSearch: "Mozilla"
            } ],
            dataOS: [ {
                string: navigator.platform,
                subString: "Win",
                identity: "Windows"
            }, {
                string: navigator.platform,
                subString: "Mac",
                identity: "Mac"
            }, {
                string: navigator.userAgent,
                subString: "iPhone",
                identity: "iPhone/iPod"
            }, {
                string: navigator.platform,
                subString: "Linux",
                identity: "Linux"
            } ]
        };
        if (BrowserDetect.init(), "Explorer" === BrowserDetect.browser) ;
    }, $rootScope.readonly = !1, $scope.scrollbarWidth = 0, $rootScope.showError = function(error) {
        var modalInstance = $modal.open({
            templateUrl: "ErrorDlgDetails.html",
            controller: "ErrorDetailsCtrl",
            resolve: {
                error: function() {
                    return error;
                }
            }
        });
        modalInstance.result.then(function(error) {
            $rootScope.error = error;
        }, function() {});
    }, $rootScope.openRichTextDlg = function(obj, key, title, disabled) {
        $modal.open({
            templateUrl: "RichTextCtrl.html",
            controller: "RichTextCtrl",
            windowClass: "app-modal-window",
            backdrop: !0,
            keyboard: !0,
            backdropClick: !1,
            resolve: {
                editorTarget: function() {
                    return {
                        key: key,
                        obj: obj,
                        disabled: disabled,
                        title: title
                    };
                }
            }
        });
    }, $rootScope.openInputTextDlg = function(obj, key, title, disabled) {
        $modal.open({
            templateUrl: "InputTextCtrl.html",
            controller: "InputTextCtrl",
            backdrop: !0,
            keyboard: !0,
            windowClass: "app-modal-window",
            backdropClick: !1,
            resolve: {
                editorTarget: function() {
                    return {
                        key: key,
                        obj: obj,
                        disabled: disabled,
                        title: title
                    };
                }
            }
        });
    }, $rootScope.showError = function(error) {
        var modalInstance = $modal.open({
            templateUrl: "ErrorDlgDetails.html",
            controller: "ErrorDetailsCtrl",
            resolve: {
                error: function() {
                    return error;
                }
            }
        });
        modalInstance.result.then(function(error) {
            $rootScope.error = error;
        }, function() {});
    }, $rootScope.cutString = function(str) {
        return str.length > 20 && (str = str.substring(0, 20) + "..."), str;
    }, $rootScope.toHTML = function(content) {
        return $sce.trustAsHtml(content);
    }, $rootScope.selectTestingType = function(value) {
        $rootScope.tabs[0] = !1, $rootScope.tabs[1] = !1, $rootScope.tabs[2] = !1, $rootScope.tabs[3] = !1, 
        $rootScope.tabs[4] = !1, $rootScope.tabs[5] = !1, $rootScope.activeTab = value, 
        $rootScope.tabs[$rootScope.activeTab] = !0, TestingSettings.setActiveTab($rootScope.activeTab);
    }, $rootScope.downloadArtifact = function(path) {
        var form = document.createElement("form");
        form.action = "api/artifact/download", form.method = "POST", form.target = "_target";
        var input = document.createElement("input");
        input.name = "path", input.value = path, form.appendChild(input), form.style.display = "none", 
        document.body.appendChild(form), form.submit();
    }, $rootScope.tabs = new Array(), $rootScope.compile = function(content) {
        return $compile(content);
    }, $rootScope.$on("$locationChangeSuccess", function() {
        $rootScope.setActive($location.path());
    }), $rootScope.openValidationResultInfo = function() {
        $modal.open({
            templateUrl: "ValidationResultInfoCtrl.html",
            windowClass: "profile-modal",
            controller: "ValidationResultInfoCtrl"
        });
    }, $rootScope.openVersionChangeDlg = function() {
        StorageService.clearAll(), $rootScope.vcModalInstance && null !== $rootScope.vcModalInstance && $rootScope.vcModalInstance.opened || ($rootScope.vcModalInstance = $modal.open({
            templateUrl: "VersionChanged.html",
            size: "lg",
            backdrop: "static",
            keyboard: "false",
            controller: "FailureCtrl",
            resolve: {
                error: function() {
                    return "";
                }
            }
        }), $rootScope.vcModalInstance.result.then(function() {
            $rootScope.clearTemplate(), $rootScope.reloadPage();
        }, function() {
            $rootScope.clearTemplate(), $rootScope.reloadPage();
        }));
    }, $rootScope.openCriticalErrorDlg = function(errorMessage) {
        StorageService.clearAll(), $rootScope.errorModalInstance && null !== $rootScope.errorModalInstance && $rootScope.errorModalInstance.opened || ($rootScope.errorModalInstance = $modal.open({
            templateUrl: "CriticalError.html",
            size: "lg",
            backdrop: !0,
            keyboard: "true",
            controller: "FailureCtrl",
            resolve: {
                error: function() {
                    return errorMessage;
                }
            }
        }), $rootScope.errorModalInstance.result.then(function() {
            $rootScope.clearTemplate(), $rootScope.reloadPage();
        }, function() {
            $rootScope.clearTemplate(), $rootScope.reloadPage();
        }));
    }, $rootScope.openUnknownDomainDlg = function(domain) {
        StorageService.clearAll(), $modal.open({
            templateUrl: "UnknownDomain.html",
            size: "lg",
            backdrop: !1,
            keyboard: "false",
            controller: "UnknownDomainCtrl",
            resolve: {
                domain: function() {
                    return domain;
                }
            }
        }).result.then(function(newDomain) {
            "New" !== newDomain ? $rootScope.selectDomain(newDomain) : $rootScope.createDomain();
        }, function() {});
    }, $rootScope.openSessionExpiredDlg = function() {
        StorageService.clearAll(), $rootScope.sessionExpiredModalInstance && null !== $rootScope.sessionExpiredModalInstance && $rootScope.sessionExpiredModalInstance.opened || ($rootScope.sessionExpiredModalInstance = $modal.open({
            templateUrl: "timedout-dialog.html",
            size: "lg",
            backdrop: !0,
            keyboard: "true",
            controller: "FailureCtrl",
            resolve: {
                error: function() {
                    return "";
                }
            }
        }), $rootScope.sessionExpiredModalInstance.result.then(function() {
            $rootScope.clearTemplate(), $rootScope.reloadPage();
        }, function() {
            $rootScope.clearTemplate(), $rootScope.reloadPage();
        }));
    }, $rootScope.clearTemplate = function() {
        $templateCache.removeAll();
    }, $rootScope.openErrorDlg = function() {
        $location.path("/error");
    }, $rootScope.pettyPrintType = function(type) {
        return "TestStep" === type ? "Test Step" : "TestCase" === type ? "Test Case" : type;
    }, $rootScope.openInvalidReqDlg = function() {
        $rootScope.errorModalInstance && null !== $rootScope.errorModalInstance && $rootScope.errorModalInstance.opened || ($rootScope.errorModalInstance = $modal.open({
            templateUrl: "InvalidReqCtrl.html",
            size: "lg",
            backdrop: !0,
            keyboard: "false",
            controller: "FailureCtrl",
            resolve: {
                error: function() {
                    return "";
                }
            }
        }), $rootScope.errorModalInstance.result.then(function() {
            $rootScope.reloadPage();
        }, function() {
            $rootScope.reloadPage();
        }));
    }, $rootScope.openNotFoundDlg = function() {
        $rootScope.errorModalInstance && null !== $rootScope.errorModalInstance && $rootScope.errorModalInstance.opened || ($rootScope.errorModalInstance = $modal.open({
            templateUrl: "NotFoundCtrl.html",
            size: "lg",
            backdrop: !0,
            keyboard: "false",
            controller: "FailureCtrl",
            resolve: {
                error: function() {
                    return "";
                }
            }
        }), $rootScope.errorModalInstance.result.then(function() {
            $rootScope.reloadPage();
        }, function() {
            $rootScope.reloadPage();
        }));
    }, $rootScope.getDomain = function() {
        return $rootScope.domain;
    }, $rootScope.nav = function(target) {
        $location.path(target);
    }, $rootScope.showSettings = function() {
        $modal.open({
            templateUrl: "views/settings/SettingsCtrl.html",
            windowClass: "upload-modal",
            keyboard: "false",
            controller: "SettingsCtrl"
        });
    }, $scope.init = function() {}, $scope.getFullName = function() {
        return userInfoService.isAuthenticated() === !0 ? userInfoService.getFullName() : "";
    }, $rootScope.isEditable = function() {
        return userInfoService.isAuthenticated() && (userInfoService.isAdmin() || userInfoService.isSupervisor()) && null != $rootScope.domain && $rootScope.domain.owner === userInfoService.getUsername();
    }, $rootScope.hasWriteAccess = function() {
        return userInfoService.isAuthenticated() && (userInfoService.isAdmin() || null != $rootScope.domain && $rootScope.domain.owner === userInfoService.getUsername());
    }, $rootScope.canPublish = function() {
        return $rootScope.hasWriteAccess() && (userInfoService.isAdmin() || userInfoService.isPublisher());
    }, $rootScope.createDomain = function() {
        var modalInstance = $modal.open({
            templateUrl: "views/domains/create.html",
            controller: "CreateDomainCtrl",
            size: "md",
            backdrop: "static",
            keyboard: !1,
            backdropClick: !1,
            resolve: {
                scope: function() {
                    return "USER";
                }
            }
        });
        modalInstance.result.then(function(newDomain) {
            newDomain ? $rootScope.selectDomain(newDomain.domain) : null !== $rootScope.domain && void 0 !== $rootScope.domain || $rootScope.reloadPage();
        }, function() {
            $rootScope.reloadPage();
        });
    }, $rootScope.domainsByOwner = {
        my: [],
        others: []
    }, $rootScope.initDomainsByOwner = function() {
        for (var i = 0; i < $rootScope.appInfo.domains.length; i++) $rootScope.appInfo.domains[i].owner === userInfoService.getUsername() ? $rootScope.domainsByOwner.my.push($rootScope.appInfo.domains[i]) : $rootScope.domainsByOwner.others.push($rootScope.appInfo.domains[i]);
    }, $rootScope.displayOwnership = function(dom) {
        return dom.owner === userInfoService.getUsername() ? "My Tool Scopes" : "Others Tool Scopes";
    }, $rootScope.orderOwnership = function(dom) {
        return dom.owner === userInfoService.getUsername() ? 0 : 1;
    };
}), angular.module("main").controller("LoginCtrl", [ "$scope", "$modalInstance", "user", "$location", function($scope, $modalInstance, user, $location) {
    $scope.user = user, $scope.cancel = function() {
        $modalInstance.dismiss("cancel");
    }, $scope.login = function() {
        $modalInstance.close($scope.user);
    }, $scope.cancelAndRedirect = function(path) {
        $modalInstance.dismiss("cancel"), $location.url(path);
    }, $scope.loginAndRedirect = function(path) {
        $modalInstance.close($scope.user), $location.url(path);
    }, $scope.loginAndReload = function() {
        $modalInstance.close($scope.user), $route.reload();
    };
} ]), angular.module("main").controller("UnknownDomainCtrl", [ "$scope", "$modalInstance", "StorageService", "$window", "domain", "userInfoService", "$rootScope", function($scope, $modalInstance, StorageService, $window, error, domain, userInfoService, $rootScope) {
    $scope.error = error, $scope.domain = domain, $scope.selectedDomain = {
        domain: null
    }, $scope.selectDomain = function() {
        StorageService.set(StorageService.APP_SELECTED_DOMAIN, $scope.selectedDomain.domain), 
        $modalInstance.close($scope.selectedDomain.domain);
    }, $scope.createNewDomain = function() {
        $modalInstance.close("New");
    }, $scope.loginReq = function() {
        $scope.$emit("event:loginRequired");
    };
} ]), angular.module("main").controller("RichTextCtrl", [ "$scope", "$modalInstance", "editorTarget", function($scope, $modalInstance, editorTarget) {
    $scope.editorTarget = editorTarget, $scope.cancel = function() {
        $modalInstance.dismiss("cancel");
    }, $scope.close = function() {
        $modalInstance.close($scope.editorTarget);
    };
} ]), angular.module("main").controller("InputTextCtrl", [ "$scope", "$modalInstance", "editorTarget", function($scope, $modalInstance, editorTarget) {
    $scope.editorTarget = editorTarget, $scope.cancel = function() {
        $modalInstance.dismiss("cancel");
    }, $scope.close = function() {
        $modalInstance.close($scope.editorTarget);
    };
} ]), angular.module("main").controller("ConfirmLogoutCtrl", [ "$scope", "$modalInstance", "$rootScope", "$http", function($scope, $modalInstance, $rootScope, $http) {
    $scope.logout = function() {
        $modalInstance.close();
    }, $scope.cancel = function() {
        $modalInstance.dismiss("cancel");
    };
} ]), angular.module("main").controller("MessageWithHexadecimalDlgCtrl", function($scope, $modalInstance, original, MessageUtil) {
    $scope.showHex = !0;
    var messageWithHexadecimal = MessageUtil.toHexadecimal(original);
    $scope.message = messageWithHexadecimal, $scope.toggleHexadecimal = function() {
        $scope.showHex = !$scope.showHex, $scope.message = $scope.showHex ? messageWithHexadecimal : original;
    }, $scope.close = function() {
        $modalInstance.dismiss("cancel");
    };
}), angular.module("main").controller("ValidationResultDetailsCtrl", function($scope, $modalInstance, selectedElement) {
    $scope.selectedElement = selectedElement, $scope.ok = function() {
        $modalInstance.close($scope.selectedElement);
    }, $scope.cancel = function() {
        $modalInstance.dismiss("cancel");
    };
}), angular.module("main").controller("ConfirmDialogCtrl", function($scope, $modalInstance) {
    $scope.confirm = function() {
        $modalInstance.close(!0);
    }, $scope.cancel = function() {
        $modalInstance.dismiss("cancel");
    };
}), angular.module("transport").controller("TransportConfigListCtrl", [ "$scope", "Transport", "StorageService", "$http", "User", "$timeout", "$rootScope", function($scope, Transport, StorageService, $http, User, $timeout, $rootScope) {
    $scope.transport = Transport, $scope.loading = !1, $scope.error = null, $scope.protocols = [], 
    $scope.selectedProtocol = null, $scope.hasConfigs = function() {
        return !!$scope.transport.configs && Object.getOwnPropertyNames($scope.transport.configs).length > 0;
    }, $scope.getProtocols = function() {
        return $scope.transport.configs ? Object.getOwnPropertyNames($scope.transport.configs) : [];
    }, $scope.getProtoDescription = function(protocol) {
        try {
            return $scope.transport.configs[protocol].description;
        } catch (error) {}
        return null;
    }, $scope.getConfigs = function() {
        return $scope.transport.configs;
    }, $scope.initTransportConfigList = function() {
        $scope.error = null;
    }, $scope.selectProtocol = function(protocolKey) {
        $scope.selectedProtocol = Transport.configs[protocolKey], $scope.$broadcast("load-transport-data", protocolKey);
    }, $scope.isActiveProtocol = function(proto) {
        return null != $scope.selectedProtocol && $scope.selectedProtocol.key === proto;
    }, $scope.toggleTransport = function(disabled) {
        if ($scope.transport.disabled = disabled, StorageService.set(StorageService.TRANSPORT_DISABLED, disabled), 
        !disabled) {
            var pr = $scope.getProtocols();
            null != pr && 1 === pr.length && $scope.selectProtocol(pr[0]);
        }
    };
} ]), angular.module("transport").controller("InitiatorConfigCtrl", function($scope, $modalInstance, htmlForm, config, domain, protocol, $http, User) {
    $scope.config = angular.copy(config), $scope.form = htmlForm, $scope.domain = domain, 
    $scope.protocol = protocol, $scope.initInitiatorConfig = function(config) {
        $scope.config = angular.copy(config);
    }, $scope.save = function() {
        var data = angular.fromJson({
            config: $scope.config,
            userId: User.info.id,
            type: "TA_INITIATOR",
            protocol: $scope.protocol
        });
        $http.post("api/transport/config/save", data), $modalInstance.close($scope.config);
    }, $scope.cancel = function() {
        $modalInstance.dismiss("cancel");
    };
}), angular.module("transport").controller("TaInitiatorConfigCtrl", function($scope, $http, User, StorageService, Transport, $rootScope, Notification) {
    $scope.transport = Transport, $scope.config = null, $scope.prevConfig = null, $scope.loading = !1, 
    $scope.error = null, $scope.proto = null, $scope.saved = !0, $scope.dom = null, 
    $scope.message = null, $scope.$on("load-transport-data", function(event, protocol) {
        $scope.proto = protocol, $scope.dom = $rootScope.domain.domain, $scope.loadData();
    }), $scope.initTaInitiatorConfig = function(domain, protocol) {
        protocol && null != protocol && domain && null != domain ? ($scope.proto = protocol, 
        $scope.dom = domain, $scope.message = null, $scope.loadData()) : $scope.error = "Protocol or domain not defined.";
    }, $scope.loadData = function() {
        $scope.config = angular.copy($scope.transport.configs[$scope.proto].data.taInitiator), 
        $scope.prevConfig = angular.copy($scope.config), $scope.message = null;
    }, $scope.save = function() {
        $scope.error = null, $scope.message = null;
        var data = angular.fromJson({
            config: $scope.config,
            userId: User.info.id,
            type: "TA_INITIATOR",
            protocol: $scope.proto,
            domain: $scope.dom
        });
        $http.post("api/transport/config/save", data).then(function(result) {
            $scope.transport.configs[$scope.proto].data.taInitiator = $scope.config, $scope.loadData(), 
            $scope.saved = !0, Notification.success({
                message: "Configuration Information Saved !",
                templateUrl: "NotificationSuccessTemplate.html",
                scope: $rootScope,
                delay: 5e3
            });
        }, function(error) {
            Notification.error({
                message: error.data,
                templateUrl: "NotificationErrorTemplate.html",
                scope: $rootScope,
                delay: 1e4
            }), $scope.saved = !1, $scope.message = null;
        });
    }, $scope.reset = function() {
        $scope.config = angular.copy($scope.prevConfig), $scope.saved = !0;
    };
}), angular.module("transport").controller("SutInitiatorConfigCtrl", function($scope, $http, Transport, $rootScope, User, Notification) {
    $scope.transport = Transport, $scope.config = null, $scope.loading = !1, $scope.saving = !1, 
    $scope.error = null, $scope.proto = null, $scope.dom = null, $scope.$on("load-transport-data", function(event, protocol) {
        $scope.proto = protocol, $scope.dom = $rootScope.domain.domain, $scope.loadData();
    }), $scope.initSutInitiatorConfig = function(domain, protocol) {
        protocol && null != protocol && domain && null != domain ? ($scope.proto = protocol, 
        $scope.dom = domain, $scope.loadData()) : $scope.error = "Protocol or domain not defined.";
    }, $scope.loadData = function() {
        $scope.config = $scope.transport.configs[$scope.proto].data.sutInitiator;
    }, $scope.save = function() {
        var config = $scope.config;
        if (config) {
            $scope.saving = !0;
            var tmpConfig = angular.copy(config);
            delete tmpConfig.password, delete tmpConfig.username;
            var data = angular.fromJson({
                config: $scope.config,
                userId: User.info.id,
                type: "SUT_INITIATOR",
                protocol: $scope.proto,
                domain: $scope.dom
            });
            $http.post("api/transport/config/save", data).then(function(result) {
                $scope.saving = !1, Notification.success({
                    message: "Configuration Information Saved !",
                    templateUrl: "NotificationSuccessTemplate.html",
                    scope: $rootScope,
                    delay: 5e3
                });
            }, function(error) {
                $scope.saving = !1, $scope.error = error, Notification.error({
                    message: error.data,
                    templateUrl: "NotificationErrorTemplate.html",
                    scope: $rootScope,
                    delay: 1e4
                });
            });
        }
    };
}), angular.module("transport").controller("CreateTransportConfigCtrl", function($scope, $modalInstance, scope, DomainsManager) {}), 
angular.module("cf").controller("CFEnvCtrl", [ "$scope", "$window", "$rootScope", "CF", "StorageService", "$timeout", "TestCaseService", "TestStepService", "$routeParams", "$location", "userInfoService", "$modalStack", "$modal", function($scope, $window, $rootScope, CB, StorageService, $timeout, TestCaseService, TestStepService, $routeParams, $location, userInfoService, $modalStack, $modal) {
    if ($scope.testCase = null, $scope.token = $routeParams.x, $scope.nav = $routeParams.nav, 
    $scope.setSubActive = function(tab) {
        $rootScope.setSubActive(tab), "/cf_execution" === tab ? $scope.$broadcast("event:cf:initExecution") : "/cf_management" === tab && $scope.$broadcast("event:cf:initManagement");
    }, void 0 !== $scope.token) userInfoService.isAuthenticated() ? $timeout(function() {
        $scope.setSubActive("/cf_management"), $scope.$broadcast("cf:uploadToken", $scope.token);
    }) : $scope.$broadcast("event:loginRequiredWithRedirect", $location.url()); else if ("manage" === $scope.nav && userInfoService.isAuthenticated()) $timeout(function() {
        $scope.setSubActive("/cf_management"), $scope.$broadcast("event:cf:manage", decodeURIComponent($routeParams.scope));
    }); else if ("execution" === $scope.nav) StorageService.set(StorageService.CF_LOADED_TESTCASE_ID_KEY, decodeURIComponent($routeParams.group)), 
    $scope.setSubActive("/cf_execution"); else {
        var tab = StorageService.get(StorageService.ACTIVE_SUB_TAB_KEY);
        "/cf_management" === tab ? $scope.setSubActive("/cf_management") : $timeout(function() {
            $scope.setSubActive("/cf_execution");
        });
    }
} ]), angular.module("cf").controller("CFTestExecutionCtrl", [ "$scope", "$http", "CF", "$window", "$modal", "$filter", "$rootScope", "CFTestPlanExecutioner", "$timeout", "StorageService", "TestCaseService", "TestStepService", "userInfoService", "$routeParams", function($scope, $http, CF, $window, $modal, $filter, $rootScope, CFTestPlanExecutioner, $timeout, StorageService, TestCaseService, TestStepService, userInfoService, $routeParams) {
    $scope.isInit = !1, $scope.cf = CF, $scope.loading = !1, $scope.loadingTC = !1, 
    $scope.error = null, $scope.testCases = [], $scope.testCase = null, $scope.tree = {}, 
    $scope.tabs = new Array(), $scope.error = null, $scope.collapsed = !1, $scope.selectedTP = {
        id: null
    }, $scope.selectedScope = {
        key: null
    }, $scope.allTestPlanScopes = [ {
        key: "USER",
        name: "Private"
    }, {
        key: "GLOBAL",
        name: "Public"
    } ], $scope.testPlanScopes = [];
    var testCaseService = new TestCaseService();
    $scope.setActiveTab = function(value) {
        $scope.tabs[0] = !1, $scope.tabs[1] = !1, $scope.tabs[2] = !1, $scope.tabs[3] = !1, 
        $scope.tabs[4] = !1, $scope.activeTab = value, $scope.tabs[$scope.activeTab] = !0;
    }, $scope.getTestCaseDisplayName = function(testCase) {
        return testCase.parentName + " - " + testCase.label;
    }, $scope.selectTP = function() {
        $scope.loadingTC = !1, $scope.errorTC = null, $scope.testCase = null, $scope.testCases = null, 
        StorageService.set(StorageService.CF_SELECTED_TESTPLAN_ID_KEY, ""), $scope.selectedTP.id && null !== $scope.selectedTP.id && "" !== $scope.selectedTP.id ? ($scope.loadingTC = !0, 
        CFTestPlanExecutioner.getTestPlan($scope.selectedTP.id).then(function(testPlan) {
            testPlan.scope === $scope.selectedScope.key ? ($scope.testCases = [ testPlan ], 
            testCaseService.buildCFTestCases(testPlan), $scope.refreshTree(), StorageService.set(StorageService.CF_SELECTED_TESTPLAN_ID_KEY, $scope.selectedTP.id), 
            $scope.loadingTC = !1) : ($scope.testCases = null, StorageService.set(StorageService.CF_SELECTED_TESTPLAN_ID_KEY, ""), 
            $scope.loadingTC = !1);
        }, function(error) {
            $scope.errorTP = "Sorry, Cannot load the test cases. Please try again";
        })) : ($scope.testCases = null, StorageService.set(StorageService.CF_SELECTED_TESTPLAN_ID_KEY, ""), 
        $scope.loadingTC = !1);
    }, $scope.selectScope = function() {
        $scope.error = null, $scope.errorTP = null, $scope.testCases = null, $scope.testPlans = null, 
        $scope.testCase = null, $scope.loadingTC = !1, $scope.loading = !1, $scope.selectedTP.id = "", 
        StorageService.set(StorageService.CF_SELECTED_TESTPLAN_SCOPE_KEY, $scope.selectedScope.key), 
        $scope.selectedScope.key && null !== $scope.selectedScope.key && "" !== $scope.selectedScope.key && null != $rootScope.domain && null != $rootScope.domain.domain ? ($scope.loading = !0, 
        CFTestPlanExecutioner.getTestPlans($scope.selectedScope.key, $rootScope.domain.domain).then(function(testPlans) {
            $scope.error = null, $scope.testPlans = $filter("orderBy")(testPlans, "position");
            var targetId = null;
            if ($scope.testPlans.length > 0) {
                if (1 === $scope.testPlans.length) targetId = $scope.testPlans[0].id; else {
                    var previousTpId = StorageService.get(StorageService.CF_SELECTED_TESTPLAN_ID_KEY);
                    if (targetId = void 0 == previousTpId || null == previousTpId ? "" : previousTpId, 
                    null != previousTpId && void 0 != previousTpId && "" != previousTpId) {
                        var tp = findTPById(previousTpId, $scope.testPlans);
                        null != tp && tp.scope === $scope.selectedScope.key && (targetId = tp.id);
                    }
                }
                if (null == targetId && userInfoService.isAuthenticated()) {
                    var lastTestPlanPersistenceId = userInfoService.getLastTestPlanPersistenceId(), tp = findTPByPersistenceId(lastTestPlanPersistenceId, $scope.testPlans);
                    null != tp && tp.scope === $scope.selectedScope.key && (targetId = tp.id);
                }
                null != targetId && ($scope.selectedTP.id = targetId.toString()), $scope.selectTP();
            } else $scope.loadingTC = !1;
            $scope.loading = !1;
        }, function(error) {
            $scope.loadingTC = !1, $scope.loading = !1, $scope.error = "Sorry, Cannot load the test plans. Please try again";
        })) : ($scope.loading = !1, StorageService.set(StorageService.CF_SELECTED_TESTPLAN_ID_KEY, ""));
    };
    var findTPByPersistenceId = function(persistentId, testPlans) {
        if (null != testPlans && void 0 != testPlans) for (var i = 0; i < testPlans.length; i++) if (testPlans[i].persistentId === persistentId) return testPlans[i];
        return null;
    }, findTPById = function(id, testPlans) {
        if (null != testPlans && void 0 != testPlans) for (var i = 0; i < testPlans.length; i++) if (testPlans[i].id === id) return testPlans[i];
        return null;
    };
    $scope.selectTestCase = function(testCase) {
        $scope.loadingTC = !0, $timeout(function() {
            var previousId = StorageService.get(StorageService.CF_LOADED_TESTCASE_ID_KEY);
            if (null != previousId && TestStepService.clearRecords(previousId), testCase.testContext && null != testCase.testContext) {
                CF.testCase = testCase, $scope.testCase = CF.testCase;
                var id = StorageService.get(StorageService.CF_LOADED_TESTCASE_ID_KEY);
                id != testCase.id && (StorageService.set(StorageService.CF_LOADED_TESTCASE_ID_KEY, testCase.id), 
                StorageService.remove(StorageService.CF_EDITOR_CONTENT_KEY)), $scope.$broadcast("cf:testCaseLoaded", $scope.testCase), 
                $scope.$broadcast("cf:profileLoaded", $scope.testCase.testContext.profile), $scope.$broadcast("cf:valueSetLibraryLoaded", $scope.testCase.testContext.vocabularyLibrary);
            }
            $scope.loadingTC = !1;
        });
    }, $scope.refreshTree = function() {
        $timeout(function() {
            if (null != $scope.testCases) if ("function" == typeof $scope.tree.build_all) {
                $scope.tree.build_all($scope.testCases);
                var testCase = null, id = StorageService.get(StorageService.CF_LOADED_TESTCASE_ID_KEY);
                if (null != id) for (var i = 0; i < $scope.testCases.length; i++) {
                    var found = testCaseService.findOneById(id, $scope.testCases[i]);
                    if (null != found) {
                        testCase = found;
                        break;
                    }
                }
                null == testCase && null != $scope.testCases && $scope.testCases.length >= 0 && (testCase = $scope.testCases[0]), 
                null != testCase && $scope.selectNode(testCase.id, testCase.type), $scope.expandAll(), 
                $scope.error = null;
            } else $scope.error = "Error: Something went wrong. Please refresh your page again.";
            $scope.loading = !1;
        }, 1e3);
    }, $scope.initTesting = function() {
        $scope.isInit || ($scope.token = $routeParams.x, $scope.nav = $routeParams.nav, 
        "execution" === $scope.nav && StorageService.set(StorageService.CF_LOADED_TESTCASE_ID_KEY, decodeURIComponent($routeParams.group)), 
        $scope.isInit = !0, $timeout(function() {
            if (userInfoService.isAuthenticated()) {
                $scope.testPlanScopes = $scope.allTestPlanScopes;
                var tmp = StorageService.get(StorageService.CF_SELECTED_TESTPLAN_SCOPE_KEY);
                $scope.selectedScope.key = tmp && null != tmp ? tmp : $scope.testPlanScopes[1].key;
            } else $scope.testPlanScopes = [ $scope.allTestPlanScopes[1] ], $scope.selectedScope.key = $scope.allTestPlanScopes[1].key;
            $scope.selectScope();
        }, 100));
    }, $scope.selectNode = function(id, type) {
        $timeout(function() {
            testCaseService.selectNodeByIdAndType($scope.tree, id, type);
        }, 0);
    }, $scope.openProfileInfo = function() {
        $modal.open({
            templateUrl: "CFProfileInfoCtrl.html",
            windowClass: "profile-modal",
            controller: "CFProfileInfoCtrl"
        });
    }, $scope.isSelectable = function(node) {
        return node.testContext && null != node.testContext;
    }, $scope.expandAll = function() {
        null != $scope.tree && $scope.tree.expand_all();
    }, $scope.collapseAll = function() {
        null != $scope.tree && $scope.tree.collapse_all();
    };
    var logoutListener = $rootScope.$on("event:logoutConfirmed", function() {
        $scope.initTesting();
    }), loginListener = $rootScope.$on("event:loginConfirmed", function() {
        $scope.initTesting();
    }), executeListener = $scope.$on("event:cf:execute", function(event, scope, group) {
        $scope.selectedScope.key = !scope || null == scope || "USER" !== scope && "GLOBAL" !== scope ? null != $scope.testPlanScopes[0] ? $scope.testPlanScopes[0].key : "GLOBAL" : scope, 
        group && null != group && ($scope.selectedTP.id = group, StorageService.set(StorageService.CF_SELECTED_TESTPLAN_ID_KEY, group)), 
        $scope.selectScope();
    }), initExecutionListener = $scope.$on("event:cf:initExecution", function() {
        $scope.initTesting();
    });
    $scope.$on("$destroy", function() {
        initExecutionListener(), executeListener(), logoutListener(), loginListener();
        var testStepId = StorageService.get(StorageService.CF_LOADED_TESTCASE_ID_KEY);
        null != testStepId && TestStepService.clearRecords(testStepId);
    });
} ]), angular.module("cf").controller("CFProfileInfoCtrl", function($scope, $modalInstance) {
    $scope.close = function() {
        $modalInstance.dismiss("cancel");
    };
}), angular.module("cf").controller("CFValidatorCtrl", [ "$scope", "$http", "CF", "$window", "$timeout", "$modal", "NewValidationResult", "$rootScope", "ServiceDelegator", "StorageService", "TestStepService", "MessageUtil", "FileUpload", "Notification", "ReportService", "userInfoService", function($scope, $http, CF, $window, $timeout, $modal, NewValidationResult, $rootScope, ServiceDelegator, StorageService, TestStepService, MessageUtil, FileUpload, Notification, ReportService, userInfoService) {
    $scope.cf = CF, $scope.testCase = CF.testCase, $scope.message = CF.message, $scope.selectedMessage = {}, 
    $scope.loading = !0, $scope.error = null, $scope.vError = null, $scope.vLoading = !0, 
    $scope.mError = null, $scope.mLoading = !0, $scope.delimeters = [], $scope.counter = 0, 
    $scope.type = "cf", $scope.loadRate = 4e3, $scope.tokenPromise = null, $scope.editorInit = !1, 
    $scope.nodelay = !1, $scope.resized = !1, $scope.selectedItem = null, $scope.activeTab = 0, 
    $scope.tError = null, $scope.tLoading = !1, $scope.hasNonPrintable = !1, $scope.dqaCodes = null != StorageService.get(StorageService.DQA_OPTIONS_KEY) ? angular.fromJson(StorageService.get(StorageService.DQA_OPTIONS_KEY)) : [], 
    $scope.showDQAOptions = function() {
        var modalInstance = $modal.open({
            templateUrl: "DQAConfig.html",
            controller: "DQAConfigCtrl",
            windowClass: "dq-modal",
            animation: !0,
            keyboard: !1,
            backdrop: !1
        });
        modalInstance.result.then(function(selectedCodes) {
            $scope.dqaCodes = selectedCodes;
        }, function() {});
    }, $scope.hasContent = function() {
        return "" != $scope.cf.message.content && null != $scope.cf.message.content;
    }, $scope.refreshEditor = function() {
        $timeout(function() {
            $scope.editor && $scope.editor.refresh();
        }, 1e3);
    }, $scope.uploadMessage = function(file, errFiles) {
        $scope.f = file, FileUpload.uploadMessage(file, errFiles).then(function(response) {
            $timeout(function() {
                file.result = response.data;
                var result = response.data, fileName = file.name;
                $scope.nodelay = !0;
                var tmp = angular.fromJson(result);
                $scope.cf.message.name = fileName, $scope.cf.editor.instance.doc.setValue(tmp.content), 
                $scope.mError = null, $scope.execute(), Notification.success({
                    message: "File " + fileName + " successfully uploaded!",
                    templateUrl: "NotificationSuccessTemplate.html",
                    scope: $rootScope,
                    delay: 3e4
                });
            });
        }, function(response) {
            $scope.mError = response.data;
        });
    }, $scope.loadMessage = function() {
        $scope.cf.testCase.testContext.message && null != $scope.cf.testCase.testContext.message && ($scope.nodelay = !0, 
        $scope.selectedMessage = $scope.cf.testCase.testContext.message, null != $scope.selectedMessage && null != $scope.selectedMessage.content ? $scope.editor.doc.setValue($scope.selectedMessage.content) : ($scope.editor.doc.setValue(""), 
        $scope.cf.message.id = null, $scope.cf.message.name = ""), $scope.execute());
    }, $scope.setLoadRate = function(value) {
        $scope.loadRate = value;
    }, $scope.initCodemirror = function() {
        $scope.editor = CodeMirror.fromTextArea(document.getElementById("cfTextArea"), {
            lineNumbers: !0,
            fixedGutter: !0,
            theme: "elegant",
            readOnly: !1,
            showCursorWhenSelecting: !0,
            gutters: [ "CodeMirror-linenumbers", "cm-edi-segment-name" ]
        }), $scope.editor.setSize("100%", 345), $scope.editor.on("keyup", function() {
            $timeout(function() {
                var msg = $scope.editor.doc.getValue();
                $scope.error = null, $scope.tokenPromise && ($timeout.cancel($scope.tokenPromise), 
                $scope.tokenPromise = void 0), CF.message.name = null, "" !== msg.trim() ? $scope.tokenPromise = $timeout(function() {
                    $scope.execute();
                }, $scope.loadRate) : $scope.execute();
            });
        }), $scope.editor.on("dblclick", function(editor) {
            $timeout(function() {
                var coordinate = ServiceDelegator.getCursorService($scope.testCase.testContext.format).getCoordinate($scope.editor, $scope.cf.tree);
                coordinate.start.index = coordinate.start.index + 1, coordinate.end.index = coordinate.end.index + 1, 
                $scope.cf.cursor.init(coordinate, !0), ServiceDelegator.getTreeService($scope.testCase.testContext.format).selectNodeByIndex($scope.cf.tree.root, CF.cursor, CF.message.content);
            });
        });
    }, $scope.validateMessage = function() {
        try {
            if ($scope.vLoading = !0, $scope.vError = null, null != $scope.cf.testCase && "" !== $scope.cf.message.content) {
                var id = $scope.cf.testCase.testContext.id, content = $scope.cf.message.content, validated = ($scope.cf.testCase.label, 
                ServiceDelegator.getMessageValidator($scope.testCase.testContext.format).validate(id, content, null, "Free", $scope.cf.testCase.testContext.dqa === !0 ? $scope.dqaCodes : [], "1223"));
                validated.then(function(mvResult) {
                    $scope.vLoading = !1, $scope.loadValidationResult(mvResult);
                }, function(error) {
                    $scope.vLoading = !1, $scope.vError = error, $scope.loadValidationResult(null);
                });
            } else $scope.loadValidationResult(null), $scope.vLoading = !1, $scope.vError = null;
        } catch (error) {
            $scope.vLoading = !1, $scope.vError = error, $scope.loadValidationResult(null);
        }
    }, $scope.loadValidationResult = function(mvResult) {
        $timeout(function() {
            $rootScope.$emit("cf:validationResultLoaded", mvResult, $scope.cf.testCase, "TestStep");
        });
    }, $scope.select = function(element) {
        if (void 0 != element && null != element.path && element.line != -1) {
            var node = ServiceDelegator.getTreeService($scope.testCase.testContext.format).selectNodeByPath($scope.cf.tree.root, element.line, element.path);
            $scope.cf.cursor.init(node.data, !1), ServiceDelegator.getEditorService($scope.testCase.testContext.format).select($scope.editor, $scope.cf.cursor);
        }
    }, $scope.clearMessage = function() {
        $scope.nodelay = !0, $scope.mError = null, $scope.editor && ($scope.editor.doc.setValue(""), 
        $scope.execute());
    }, $scope.saveMessage = function() {
        $scope.cf.message.download();
    }, $scope.parseMessage = function() {
        try {
            if (null != $scope.cf.testCase && null != $scope.cf.testCase.testContext && "" != $scope.cf.message.content) {
                $scope.tLoading = !0;
                var parsed = ServiceDelegator.getMessageParser($scope.testCase.testContext.format).parse($scope.cf.testCase.testContext.id, $scope.cf.message.content);
                parsed.then(function(value) {
                    $scope.tLoading = !1, $scope.cf.tree.root.build_all(value.elements), ServiceDelegator.updateEditorMode($scope.editor, value.delimeters, $scope.cf.testCase.testContext.format), 
                    ServiceDelegator.getEditorService($scope.testCase.testContext.format).setEditor($scope.editor), 
                    ServiceDelegator.getTreeService($scope.testCase.testContext.format).setEditor($scope.editor);
                }, function(error) {
                    $scope.tLoading = !1, $scope.tError = error;
                });
            } else "function" == typeof $scope.cf.tree.root.build_all && $scope.cf.tree.root.build_all([]), 
            $scope.tError = null, $scope.tLoading = !1;
        } catch (error) {
            $scope.tLoading = !1, $scope.tError = error;
        }
    }, $scope.onNodeSelect = function(node) {
        ServiceDelegator.getTreeService($scope.testCase.testContext.format).getEndIndex(node, $scope.cf.message.content), 
        $scope.cf.cursor.init(node.data, !1), ServiceDelegator.getEditorService($scope.testCase.testContext.format).select($scope.editor, $scope.cf.cursor);
    }, $scope.execute = function() {
        null != $scope.cf.testCase && ($scope.tokenPromise && ($timeout.cancel($scope.tokenPromise), 
        $scope.tokenPromise = void 0), $scope.error = null, $scope.tError = null, $scope.mError = null, 
        $scope.vError = null, $scope.cf.message.content = $scope.editor.doc.getValue(), 
        $scope.setHasNonPrintableCharacters(), StorageService.set(StorageService.CF_EDITOR_CONTENT_KEY, $scope.cf.message.content), 
        $scope.validateMessage(), $scope.parseMessage(), $scope.refreshEditor());
    }, $scope.removeDuplicates = function() {
        $scope.vLoading = !0, $scope.$broadcast("cf:removeDuplicates");
    }, $scope.initValidation = function() {
        $scope.vLoading = !1, $scope.tLoading = !1, $scope.mLoading = !1, $scope.error = null, 
        $scope.tError = null, $scope.mError = null, $scope.vError = null, $scope.cf.savedReports = [], 
        $scope.$on("cf:testCaseLoaded", function(event, testCase) {
            if ($scope.testCase = testCase, null != $scope.testCase) {
                var content = null == StorageService.get(StorageService.CF_EDITOR_CONTENT_KEY) ? "" : StorageService.get(StorageService.CF_EDITOR_CONTENT_KEY);
                $scope.nodelay = !0, $scope.mError = null, $timeout(function() {
                    $scope.editor && null !== $scope.editor || ($scope.initCodemirror(), $scope.refreshEditor()), 
                    $scope.cf.editor = ServiceDelegator.getEditor($scope.testCase.testContext.format), 
                    $scope.cf.editor.instance = $scope.editor, $scope.cf.cursor = ServiceDelegator.getCursor($scope.testCase.testContext.format), 
                    TestStepService.clearRecords($scope.testCase.id), $scope.editor && ($scope.editor.doc.setValue(content), 
                    $scope.execute());
                }, 500), userInfoService.isAuthenticated() && $rootScope.isReportSavingSupported() && $timeout(function() {
                    ReportService.getAllTSByAccountIdAndDomainAndtestStepId($rootScope.domain.domain, $scope.testCase.persistentId).then(function(reports) {
                        null !== reports ? ($scope.cf.selectedSavedReport = null, $scope.cf.savedReports = reports) : ($scope.cf.savedReports = [], 
                        $scope.cf.selectedSavedReport = null);
                    }, function(error) {
                        $scope.cf.selectedSavedReport = null, $scope.cf.savedReports = [], $scope.loadingAll = !1, 
                        $scope.error = "Sorry, Cannot load the reports. Please try again. \n DEBUG:" + error;
                    });
                }, 100);
            }
        }), $rootScope.$on("cf:updateSavedReports", function(event, teptStep) {
            userInfoService.isAuthenticated() && $rootScope.isReportSavingSupported() && $timeout(function() {
                ReportService.getAllTSByAccountIdAndDomainAndtestStepId($rootScope.domain.domain, teptStep.persistentId).then(function(reports) {
                    null !== reports ? ($scope.cf.selectedSavedReport = null, $scope.cf.savedReports = reports) : ($scope.cf.savedReports = [], 
                    $scope.cf.selectedSavedReport = null);
                }, function(error) {
                    $scope.cf.selectedSavedReport = null, $scope.cf.savedReports = [], $scope.loadingAll = !1, 
                    $scope.error = "Sorry, Cannot load the reports. Please try again. \n DEBUG:" + error;
                });
            }, 100);
        }), $rootScope.$on("cf:duplicatesRemoved", function(event, report) {
            $scope.vLoading = !1;
        });
    }, $scope.expandAll = function() {
        null != $scope.cf.tree.root && $scope.cf.tree.root.expand_all();
    }, $scope.collapseAll = function() {
        null != $scope.cf.tree.root && $scope.cf.tree.root.collapse_all();
    }, $scope.expandMessageAll = function() {
        null != $scope.cf.tree.root && $scope.cf.tree.root.expand_all();
    }, $scope.collapseMessageAll = function() {
        null != $scope.cf.tree.root && $scope.cf.tree.root.collapse_all();
    }, $scope.setHasNonPrintableCharacters = function() {
        $scope.hasNonPrintable = MessageUtil.hasNonPrintable($scope.cf.message.content);
    }, $scope.showMessageWithHexadecimal = function() {
        $modal.open({
            templateUrl: "MessageWithHexadecimal.html",
            controller: "MessageWithHexadecimalDlgCtrl",
            windowClass: "valueset-modal",
            animation: !1,
            keyboard: !0,
            backdrop: !0,
            resolve: {
                original: function() {
                    return $scope.cf.message.content;
                }
            }
        });
    };
} ]), angular.module("cf").controller("CFReportCtrl", [ "$scope", "$sce", "$http", "CF", function($scope, $sce, $http, CF) {
    $scope.cf = CF;
} ]), angular.module("cf").controller("CFSavedReportCtrl", [ "$scope", "$sce", "$http", "CF", "ReportService", "$modal", function($scope, $sce, $http, CF, ReportService, $modal) {
    $scope.cf = CF, $scope.selectReport = function(report) {
        $scope.loading = !0, ReportService.getUserTSReportHTML(report.id).then(function(report) {
            null !== report && ($scope.cf.selectedSavedReport = report);
        }, function(error) {
            $scope.error = "Sorry, Cannot load the report data. Please try again. \n DEBUG:" + error;
        }).finally(function() {
            $scope.loading = !1;
        });
    }, $scope.downloadAs = function(format) {
        if ($scope.cf.selectedSavedReport) return ReportService.downloadUserTestStepValidationReport($scope.cf.selectedSavedReport.id, format);
    }, $scope.deleteReport = function(report) {
        var modalInstance = $modal.open({
            templateUrl: "confirmReportDelete.html",
            controller: "ConfirmDialogCtrl",
            size: "md",
            backdrop: !0,
            keyboard: !0
        });
        modalInstance.result.then(function(resultDiag) {
            resultDiag && ReportService.deleteTSReport(report.id).then(function(result) {
                var index = $scope.reports.indexOf(report);
                index > -1 && $scope.reports.splice(index, 1), Notification.success({
                    message: "Report deleted successfully!",
                    templateUrl: "NotificationSuccessTemplate.html",
                    scope: $rootScope,
                    delay: 5e3
                });
            }, function(error) {
                Notification.error({
                    message: "Report deletion failed! <br>If error persists, please contact the website administrator.",
                    templateUrl: "NotificationErrorTemplate.html",
                    scope: $rootScope,
                    delay: 1e4
                });
            });
        }, function(resultDiag) {});
    };
} ]), angular.module("cf").controller("CFVocabularyCtrl", [ "$scope", "CF", function($scope, CF) {
    $scope.cf = CF;
} ]), angular.module("cf").controller("CFProfileViewerCtrl", [ "$scope", "CF", "$rootScope", function($scope, CF, $rootScope) {
    $scope.cf = CF;
} ]), angular.module("cf").controller("CFTestManagementCtrl", [ "$scope", "$http", "$window", "$filter", "$rootScope", "$timeout", "StorageService", "TestCaseService", "TestStepService", "FileUploader", "Notification", "userInfoService", "CFTestPlanManager", "modalService", "$modalStack", "$modal", "$routeParams", "$location", function($scope, $http, $window, $filter, $rootScope, $timeout, StorageService, TestCaseService, TestStepService, FileUploader, Notification, userInfoService, CFTestPlanManager, modalService, $modalStack, $modal, $routeParams, $location) {
    $scope.selectedScope = {
        key: "USER"
    }, $scope.groupScopes = [], $scope.allGroupScopes = [ {
        key: "USER",
        name: "Private"
    }, {
        key: "GLOBAL",
        name: "Public"
    } ], $scope.uploaded = !1, $scope.testcase = null, $scope.existingTP = {
        selected: null
    }, $scope.selectedTP = {
        id: null
    }, $scope.categoryNodes = [], $scope.profileValidationErrors = [], $scope.valueSetValidationErrors = [], 
    $scope.constraintValidationErrors = [], $scope.existingTestPlans = null, $scope.tmpNewMessages = [], 
    $scope.tmpOldMessages = [];
    new TestCaseService();
    $scope.token = $routeParams.x, $scope.positions = function(messages) {
        for (var array = new Array(messages.length), index = 0; index < array.length; index++) array[index] = index + 1;
        return array;
    }, $scope.filterMessages = function(array) {
        return array = _.reject(array, function(item) {
            return 1 == item.removed;
        }), array = $filter("orderBy")(array, "position");
    }, $scope.$on("event:cf:manage", function(event, targetScope) {
        $timeout(function() {
            $rootScope.isCfManagementSupported() && userInfoService.isAuthenticated() && ($scope.testcase = null, 
            $scope.groupScopes = $scope.allGroupScopes, targetScope !== $scope.allGroupScopes[1].key || userInfoService.isAdmin() || userInfoService.isSupervisor() || (targetScope = $scope.allGroupScopes[0]), 
            $scope.selectedScope = {
                key: targetScope
            }, $scope.testcase = null, $scope.selectScope());
        }, 1e3);
    });
    var logoutListener = $rootScope.$on("event:logoutConfirmed", function() {
        $scope.initManagement();
    }), initManagementListener = $scope.$on("event:cf:initManagement", function() {
        $scope.initManagement();
    }), loginListener = $rootScope.$on("event:loginConfirmed", function() {
        $scope.initManagement();
    });
    $scope.$on("$destroy", function() {
        initManagementListener(), logoutListener(), loginListener();
    }), $scope.initManagement = function() {
        $timeout(function() {
            $rootScope.isCfManagementSupported() && userInfoService.isAuthenticated() && $rootScope.hasWriteAccess() && (userInfoService.isAdmin() || userInfoService.isSupervisor() ? $scope.groupScopes = $scope.allGroupScopes : $scope.groupScopes = [ $scope.allGroupScopes[0] ], 
            $scope.selectedScope.key = $scope.groupScopes[0].key, $scope.testcase = null, $scope.selectScope(), 
            void 0 !== $scope.token && null !== $scope.token && userInfoService.isAuthenticated() && CFTestPlanManager.getTokenProfiles("hl7v2", $scope.token).then(function(response) {
                if (0 == response.success) void 0 === response.debugError ? (Notification.error({
                    message: "The zip file you uploaded is not valid, please check and correct the error(s)",
                    templateUrl: "NotificationErrorTemplate.html",
                    scope: $rootScope,
                    delay: 1e4
                }), $scope.profileValidationErrors = angular.fromJson(response.profileErrors), $scope.valueSetValidationErrors = angular.fromJson(response.constraintsErrors), 
                $scope.constraintValidationErrors = angular.fromJson(response.vsErrors)) : Notification.error({
                    message: "  " + response.message + "<br>" + response.debugError,
                    templateUrl: "NotificationErrorTemplate.html",
                    scope: $rootScope,
                    delay: 1e4
                }); else {
                    if ($scope.profileMessages = response.profiles, $scope.tmpNewMessages = $scope.filterMessages($scope.profileMessages), 
                    $scope.tmpNewMessages.length > 0) for (var i = 0; i < $scope.tmpNewMessages.length; i++) $scope.tmpNewMessages[i].position = i + 1;
                    $scope.originalProfileMessages = angular.copy($scope.profileMessages);
                }
            }, function(response) {}));
        }, 1e3);
    }, $scope.selectScope = function() {
        $scope.existingTestPlans = null, $scope.selectedTP.id = "", $scope.error = null, 
        $scope.testcase = null, $scope.existingTP.selected = null, $scope.oldProfileMessages = null, 
        $scope.testCases = null, StorageService.set(StorageService.CF_MANAGE_SELECTED_TESTPLAN_ID_KEY, null), 
        $scope.selectedScope.key && null !== $scope.selectedScope.key && "" !== $scope.selectedScope.key && null != $rootScope.domain && null != $rootScope.domain.domain && CFTestPlanManager.getTestPlans($scope.selectedScope.key, $rootScope.domain.domain).then(function(testPlans) {
            $scope.existingTestPlans = testPlans;
            var targetId = null;
            if (1 === $scope.existingTestPlans.length && (targetId = $scope.existingTestPlans[0].id), 
            null == targetId) {
                var previousTpId = StorageService.get(StorageService.CF_MANAGE_SELECTED_TESTPLAN_ID_KEY);
                targetId = void 0 == previousTpId || null == previousTpId ? "" : previousTpId;
            }
            null != targetId && ($scope.selectedTP.id = targetId.toString(), $scope.selectTestPlan());
        }, function(error) {
            $scope.error = "Sorry, Failed to load the profile groups. Please try again";
        });
    }, $scope.selectTestPlan = function() {
        $scope.loadingTP = !1, $scope.errorTP = null, $scope.errorTC = null, $scope.error = null, 
        $scope.selectedTP.id && null !== $scope.selectedTP.id && "" !== $scope.selectedTP.id ? ($scope.loadingTP = !0, 
        CFTestPlanManager.getTestPlan($scope.selectedTP.id).then(function(testPlan) {
            $scope.testCases = [ testPlan ], $scope.testcase = null, $scope.generateTreeNodes(testPlan), 
            $scope.selectGroup(testPlan), StorageService.set(StorageService.CF_MANAGE_SELECTED_TESTPLAN_ID_KEY, $scope.selectedTP.id), 
            $scope.loadingTP = !1;
        }, function(error) {
            $scope.errorTP = "Sorry, Cannot load the test cases. Please try again";
        })) : ($scope.testCases = null, StorageService.set(StorageService.CF_MANAGE_SELECTED_TESTPLAN_ID_KEY, ""), 
        $scope.loadingTP = !1);
    }, $scope.loadOldProfileMessages = function(groupId, groupType) {
        $scope.OldMessagesErrors = null, $scope.oldProfileMessages = null, $scope.originalOldProfileMessages = null, 
        $scope.tmpOldMessages = null, null != groupId && ("TestPlan" == groupType ? CFTestPlanManager.getTestPlanProfiles(groupId).then(function(profiles) {
            $scope.oldProfileMessages = profiles, $scope.tmpOldMessages = $scope.filterMessages($scope.oldProfileMessages), 
            $scope.originalOldProfileMessages = angular.copy($scope.oldProfileMessages);
        }, function(error) {
            $scope.OldMessagesErrors = "Sorry, Failed to load the existing profiles. Please try again";
        }) : CFTestPlanManager.getTestStepGroupProfiles(groupId).then(function(profiles) {
            $scope.oldProfileMessages = profiles, $scope.tmpOldMessages = $scope.filterMessages($scope.oldProfileMessages), 
            $scope.originalOldProfileMessages = angular.copy($scope.oldProfileMessages);
        }, function(error) {
            $scope.OldMessagesErrors = "Sorry, Failed to load the existing profiles. Please try again";
        }));
    }, $scope.categorize = function(profileGroups) {
        var categoryMap = {};
        return null != profileGroups && profileGroups.length > 0 && angular.forEach(profileGroups, function(profileGroup) {
            void 0 == categoryMap[profileGroup.category] && (categoryMap[profileGroup.category] = []), 
            categoryMap[profileGroup.category].push(profileGroup);
        }), categoryMap;
    }, $scope.generateTreeNodes = function(node) {
        if ("TestObject" !== node.type) {
            node.nav || (node.nav = {});
            node.testStepGroups && (node.children ? angular.forEach(node.testStepGroups, function(testStepGroup) {
                node.children.push(testStepGroup), testStepGroup.nav = {}, testStepGroup.parent = {
                    id: node.id,
                    type: node.type
                }, $scope.generateTreeNodes(testStepGroup);
            }) : (node.children = node.testStepGroups, angular.forEach(node.children, function(testStepGroup) {
                testStepGroup.nav = {}, testStepGroup.parent = {
                    id: node.id,
                    type: node.type
                }, $scope.generateTreeNodes(testStepGroup);
            })), node.children = $filter("orderBy")(node.children, "position"), delete node.testStepGroups);
        }
    }, $scope.deleteGroup = function(node) {
        "TestPlan" === node.type ? $scope.deleteTestPlan(node) : $scope.deleteTestStepGroup(node);
    }, $scope.deleteTestPlan = function(node) {
        var modalInstance = $modal.open({
            templateUrl: "views/cf/manage/confirm-delete-group.html",
            controller: "ConfirmDialogCtrl",
            size: "md",
            backdrop: "static",
            keyboard: !1
        });
        modalInstance.result.then(function(result) {
            result && CFTestPlanManager.deleteTestPlan(node).then(function(result) {
                if ("SUCCESS" === result.status) {
                    var testPlan = $scope.findTestPlan(node.id, $scope.existingTestPlans), index = $scope.existingTestPlans.indexOf(testPlan);
                    index > -1 && $scope.existingTestPlans.splice(index, 1), $scope.testCases = null, 
                    Notification.success({
                        message: "Profile group deleted successfully !",
                        templateUrl: "NotificationSuccessTemplate.html",
                        scope: $rootScope,
                        delay: 5e3
                    }), null != $scope.testcase && node.id === $scope.testcase.groupId && "TestPlan" === $scope.testcase.type && $scope.selectGroup(null), 
                    $scope.selectScope();
                } else $scope.error = result.message;
            }, function(error) {
                $scope.error = "Sorry, Cannot delete the profile group. Please try again";
            });
        }, function(result) {});
    }, $scope.deleteTestStepGroup = function(node) {
        var modalInstance = $modal.open({
            templateUrl: "views/cf/manage/confirm-delete-group.html",
            controller: "ConfirmDialogCtrl",
            size: "md",
            backdrop: "static",
            keyboard: !1
        });
        modalInstance.result.then(function(result) {
            result && CFTestPlanManager.deleteTestStepGroup(node).then(function(result) {
                "SUCCESS" === result.status ? (Notification.success({
                    message: "Profile group deleted successfully !",
                    templateUrl: "NotificationSuccessTemplate.html",
                    scope: $rootScope,
                    delay: 5e3
                }), null != $scope.testcase && node.id === $scope.testcase.groupId && "TestStepGroup" === $scope.testcase.type && $scope.selectGroup(null), 
                $scope.selectTestPlan()) : $scope.error = result.message;
            }, function(error) {
                $scope.error = "Sorry, Cannot delete the profile group. Please try again";
            });
        }, function(result) {});
    }, $scope.findGroup = function(groupId, groupType, children) {
        if (null != groupId && "" != groupId && children && null != children && children.length > 0) for (var i = 0; i < children.length; i++) {
            if (children[i].id == groupId && children[i].type === groupType) return children[i];
            var found = $scope.findGroup(groupId, groupType, children[i].children);
            if (null != found) return found;
        }
        return null;
    }, $scope.findTestPlan = function(groupId, children) {
        if (null != groupId && "" != groupId && children && null != children && children.length > 0) for (var i = 0; i < children.length; i++) if (children[i].id === groupId) return children[i];
        return null;
    }, $scope.findGroupByPersistenceId = function(persistentId) {
        if (null != persistentId && "" != persistentId && null != $scope.existingTestPlans && $scope.existingTestPlans.length > 0) for (var i = 0; i < $scope.existingTestPlans.length; i++) if ($scope.existingTestPlans[i].persistentId == persistentId) return $scope.existingTestPlans[i];
        return null;
    }, $scope.selectGroup = function(node) {
        null != node && ($scope.executionError = null, $scope.error = null, $scope.selectedNode = node, 
        $scope.oldProfileMessages = [], $scope.originalOldProfileMessages = angular.copy($scope.oldProfileMessages), 
        $scope.testcase = {}, $scope.testcase.scope = $scope.selectedScope.key, $scope.testcase.name = node.name, 
        $scope.testcase.description = node.description, $scope.testcase.groupId = node.id, 
        $scope.testcase.persistentId = node.persistentId, $scope.testcase.type = node.type, 
        $scope.testcase.position = node.position, $scope.loadOldProfileMessages(node.id, node.type));
    }, $scope.createTestPlan = function() {
        var modalInstance = $modal.open({
            templateUrl: "views/cf/manage/createProfileGroup.html",
            controller: "CreateTestPlanCtrl",
            size: "lg",
            backdrop: "static",
            keyboard: !1,
            backdropClick: !1,
            resolve: {
                scope: function() {
                    return $scope.selectedScope.key;
                },
                domain: function() {
                    return $rootScope.domain.domain;
                },
                position: function() {
                    return $scope.existingTestPlans ? $scope.existingTestPlans.length + 1 : 1;
                }
            }
        });
        modalInstance.result.then(function(newTestPlan) {
            newTestPlan && ($scope.existingTestPlans && null != $scope.existingTestPlans || ($scope.existingTestPlans = []), 
            StorageService.set(StorageService.CF_MANAGE_SELECTED_TESTPLAN_ID_KEY, null), $scope.existingTestPlans.push(newTestPlan), 
            $scope.selectedTP.id = newTestPlan.id, $scope.selectTestPlan());
        });
    }, $scope.addNewTestStepGroup = function(parentNode) {
        var modalInstance = $modal.open({
            templateUrl: "views/cf/manage/createProfileGroup.html",
            controller: "CreateTestStepGroupCtrl",
            size: "lg",
            backdrop: "static",
            keyboard: !1,
            backdropClick: !1,
            resolve: {
                scope: function() {
                    return $scope.selectedScope.key;
                },
                domain: function() {
                    return $rootScope.domain.domain;
                },
                position: function() {
                    return parentNode.children ? parentNode.children.length + 1 : 1;
                },
                parentNode: function() {
                    return parentNode;
                }
            }
        });
        modalInstance.result.then(function(group) {
            if (group) {
                var treeNode = {};
                treeNode.id = group.id, treeNode.persistentId = group.persistentId, treeNode.name = group.name, 
                treeNode.position = group.position, treeNode.description = group.description, treeNode.scope = group.scope, 
                treeNode.type = group.type, treeNode.nav = {}, treeNode.parent = {
                    id: parentNode.id,
                    type: parentNode.type
                }, parentNode.children || (parentNode.children = []), parentNode.children.push(treeNode), 
                parentNode.children = $filter("orderBy")(parentNode.children, "position"), $scope.selectGroup(group);
            }
        });
    }, $scope.afterSave = function(token) {
        $timeout(function() {
            if (null != token && token) {
                var group = StorageService.get(StorageService.CF_MANAGE_SELECTED_TESTPLAN_ID_KEY);
                $location.url("/cf?nav=execution&scope=" + $scope.selectedScope.key + "&group=" + group);
            }
        });
    }, $scope.publishGroup = function() {
        $scope.error = null, $scope.executionError = [];
        var modalInstance = $modal.open({
            templateUrl: "views/cf/manage/confirm-publish-group.html",
            controller: "ConfirmDialogCtrl",
            size: "md",
            backdrop: "static",
            keyboard: !1
        });
        modalInstance.result.then(function(result) {
            result && ($scope.loading = !0, $scope.executionError = null, $scope.loading = !0, 
            $scope.error = null, $scope.executionError = [], CFTestPlanManager.saveTestPlan("hl7v2", $scope.testcase.scope, $scope.token, $scope.getUpdatedProfiles(), $scope.getRemovedProfiles(), $scope.getAddedProfiles(), $scope.testcase).then(function(result) {
                "SUCCESS" === result.status && CFTestPlanManager.publishTestPlan($scope.testcase.groupId).then(function(result) {
                    if ("SUCCESS" === result.status) {
                        if ($scope.selectedNode = $scope.testCases[0], null != $scope.selectedNode) {
                            $scope.selectedNode.name = $scope.testcase.name, $scope.selectedNode.description = $scope.testcase.description;
                            var testPlan = $scope.findTestPlan($scope.selectedNode.id, $scope.existingTestPlans);
                            testPlan.name = $scope.testcase.name, testPlan.description = $scope.testcase.description, 
                            Notification.success({
                                message: "Profile Group saved successfully!",
                                templateUrl: "NotificationSuccessTemplate.html",
                                scope: $rootScope,
                                delay: 5e3
                            }), $scope.uploaded = !1, $scope.profileMessages = [], $scope.profileMessagesTmp = [], 
                            $scope.oldProfileMessages = [], $scope.tmpNewMessages = [], $scope.tmpOldMessages = [], 
                            $scope.originalOldProfileMessages = [], $scope.originalProfileMessages = [], $scope.selectedScope.key = "GLOBAL", 
                            $scope.selectScope(), $scope.selectGroup($scope.selectedNode), Notification.success({
                                message: "Profile Group has been successfully published !",
                                templateUrl: "NotificationSuccessTemplate.html",
                                scope: $rootScope,
                                delay: 5e3
                            }), $scope.afterSave($scope.token);
                        }
                    } else $scope.executionError.push(response.debugError);
                    $scope.loading = !1;
                }, function(error) {
                    $scope.loading = !1, $scope.executionError.push(error.data);
                });
            }, function(error) {
                $scope.loading = !1, $scope.executionError.push(error.data);
            }));
        });
    }, $scope.unPublishGroup = function() {
        $scope.error = null, $scope.executionError = [];
        var modalInstance = $modal.open({
            templateUrl: "views/cf/manage/confirm-unpublish-group.html",
            controller: "ConfirmDialogCtrl",
            size: "md",
            backdrop: "static",
            keyboard: !1
        });
        modalInstance.result.then(function(result) {
            result && ($scope.loading = !0, $scope.executionError = null, $scope.loading = !0, 
            $scope.error = null, $scope.executionError = [], CFTestPlanManager.saveTestPlan("hl7v2", "USER", $scope.token, $scope.getUpdatedProfiles(), $scope.getRemovedProfiles(), $scope.getAddedProfiles(), $scope.testcase).then(function(result) {
                "SUCCESS" === result.status && CFTestPlanManager.unPublishTestPlan($scope.testcase.groupId).then(function(result) {
                    if ("SUCCESS" === result.status) {
                        if ($scope.selectedNode = $scope.testCases[0], null != $scope.selectedNode) {
                            $scope.selectedNode.name = $scope.testcase.name, $scope.selectedNode.description = $scope.testcase.description;
                            var testPlan = $scope.findTestPlan($scope.selectedNode.id, $scope.existingTestPlans);
                            testPlan.name = $scope.testcase.name, testPlan.description = $scope.testcase.description, 
                            Notification.success({
                                message: "Profile Group saved successfully!",
                                templateUrl: "NotificationSuccessTemplate.html",
                                scope: $rootScope,
                                delay: 5e3
                            }), $scope.uploaded = !1, $scope.profileMessages = [], $scope.profileMessagesTmp = [], 
                            $scope.oldProfileMessages = [], $scope.tmpNewMessages = [], $scope.tmpOldMessages = [], 
                            $scope.originalOldProfileMessages = [], $scope.originalProfileMessages = [], $scope.selectedScope.key = "USER", 
                            $scope.selectScope(), $scope.selectGroup($scope.selectedNode), Notification.success({
                                message: "Profile Group has been successfully published !",
                                templateUrl: "NotificationSuccessTemplate.html",
                                scope: $rootScope,
                                delay: 5e3
                            }), $scope.afterSave($scope.token);
                        }
                    } else $scope.executionError.push(response.debugError);
                    $scope.loading = !1;
                }, function(error) {
                    $scope.loading = !1, $scope.executionError.push(error.data);
                });
            }, function(error) {
                $scope.loading = !1, $scope.executionError.push(error.data);
            }));
        });
    }, $scope.unPublishGroup = function() {
        $scope.error = null, $scope.executionError = [];
        var modalInstance = $modal.open({
            templateUrl: "views/cf/manage/confirm-unpublish-group.html",
            controller: "ConfirmDialogCtrl",
            size: "md",
            backdrop: "static",
            keyboard: !1
        });
        modalInstance.result.then(function(result) {
            result && ($scope.loading = !0, $scope.executionError = null, $scope.loading = !0, 
            $scope.error = null, $scope.executionError = [], CFTestPlanManager.saveTestPlan("hl7v2", "USER", $scope.token, $scope.getUpdatedProfiles(), $scope.getRemovedProfiles(), $scope.getAddedProfiles(), $scope.testcase).then(function(result) {
                "SUCCESS" === result.status && CFTestPlanManager.unPublishTestPlan($scope.testcase.groupId).then(function(result) {
                    if ("SUCCESS" === result.status) {
                        if ($scope.selectedNode = $scope.testCases[0], null != $scope.selectedNode) {
                            $scope.selectedNode.name = $scope.testcase.name, $scope.selectedNode.description = $scope.testcase.description;
                            var testPlan = $scope.findTestPlan($scope.selectedNode.id, $scope.existingTestPlans);
                            testPlan.name = $scope.testcase.name, testPlan.description = $scope.testcase.description, 
                            Notification.success({
                                message: "Profile Group saved successfully!",
                                templateUrl: "NotificationSuccessTemplate.html",
                                scope: $rootScope,
                                delay: 5e3
                            }), $scope.uploaded = !1, $scope.profileMessages = [], $scope.profileMessagesTmp = [], 
                            $scope.oldProfileMessages = [], $scope.tmpNewMessages = [], $scope.tmpOldMessages = [], 
                            $scope.originalOldProfileMessages = [], $scope.originalProfileMessages = [], $scope.selectedScope.key = "USER", 
                            $scope.selectScope(), $scope.selectGroup($scope.selectedNode), Notification.success({
                                message: "Profile Group has been successfully published !",
                                templateUrl: "NotificationSuccessTemplate.html",
                                scope: $rootScope,
                                delay: 5e3
                            }), $scope.afterSave($scope.token);
                        }
                    } else $scope.executionError.push(response.debugError);
                    $scope.loading = !1;
                }, function(error) {
                    $scope.loading = !1, $scope.executionError.push(error.data);
                });
            }, function(error) {
                $scope.loading = !1, $scope.executionError.push(error.data);
            }));
        });
    }, $scope.saveGroup = function(node) {
        "TestPlan" === node.type ? $scope.saveTestPlan() : $scope.saveTestStepGroup();
    }, $scope.saveTestPlan = function() {
        $scope.loading = !0, $scope.error = null, $scope.executionError = [], CFTestPlanManager.saveTestPlan("hl7v2", $scope.testcase.scope, $scope.token, $scope.getUpdatedProfiles(), $scope.getRemovedProfiles(), $scope.getAddedProfiles(), $scope.testcase).then(function(result) {
            if ("SUCCESS" === result.status) {
                if ($scope.selectedNode = $scope.testCases[0], null != $scope.selectedNode) {
                    $scope.selectedNode.name = $scope.testcase.name, $scope.selectedNode.description = $scope.testcase.description;
                    var testPlan = $scope.findTestPlan($scope.selectedNode.id, $scope.existingTestPlans);
                    testPlan.name = $scope.testcase.name, testPlan.description = $scope.testcase.description, 
                    Notification.success({
                        message: "Profile Group saved successfully!",
                        templateUrl: "NotificationSuccessTemplate.html",
                        scope: $rootScope,
                        delay: 5e3
                    }), $scope.uploaded = !1, $scope.profileMessages = [], $scope.oldProfileMessages = [], 
                    $scope.tmpNewMessages = [], $scope.tmpOldMessages = [], $scope.originalOldProfileMessages = [], 
                    $scope.originalProfileMessages = [], $scope.selectGroup($scope.selectedNode), $scope.afterSave($scope.token), 
                    $scope.token = null;
                }
            } else $scope.executionError = result.message;
            $scope.loading = !1;
        }, function(error) {
            $scope.loading = !1, $scope.executionError = error.data;
        });
    }, $scope.saveTestStepGroup = function() {
        $scope.loading = !0, $scope.error = null, $scope.executionError = null, CFTestPlanManager.saveTestStepGroup("hl7v2", $scope.testcase.scope, $scope.token, $scope.getUpdatedProfiles(), $scope.getRemovedProfiles(), $scope.getAddedProfiles(), $scope.testcase).then(function(result) {
            "SUCCESS" === result.status ? ($scope.selectedNode = $scope.findGroup($scope.testcase.groupId, "TestStepGroup", $scope.testCases), 
            null != $scope.selectedNode && ($scope.selectedNode.name = $scope.testcase.name, 
            $scope.selectedNode.description = $scope.testcase.description, Notification.success({
                message: "Profile Group saved successfully!",
                templateUrl: "NotificationSuccessTemplate.html",
                scope: $rootScope,
                delay: 5e3
            }), $scope.uploaded = !1, $scope.profileMessages = [], $scope.profileMessagesTmp = [], 
            $scope.oldProfileMessages = [], $scope.tmpNewMessages = [], $scope.tmpOldMessages = [], 
            $scope.originalOldProfileMessages = [], $scope.originalProfileMessages = [], $scope.selectGroup($scope.selectedNode), 
            $scope.afterSave($scope.token), $scope.token = null)) : $scope.executionError.push(response.debugError), 
            $scope.loading = !1;
        }, function(error) {
            $scope.loading = !1, $scope.executionError.push(error.data);
        });
    }, $scope.reset = function() {
        $scope.error = null, $scope.executionError = [];
        var modalInstance = $modal.open({
            templateUrl: "views/cf/manage/confirm-reset-group.html",
            controller: "ConfirmDialogCtrl",
            size: "md",
            backdrop: "static",
            keyboard: !1
        });
        modalInstance.result.then(function(result) {
            if (result) {
                if (null != $scope.selectedNode && ($scope.testcase.name = $scope.selectedNode.name, 
                $scope.testcase.description = $scope.selectedNode.description), $scope.profileMessages = angular.copy($scope.originalProfileMessages), 
                $scope.tmpNewMessages = $scope.filterMessages($scope.profileMessages), $scope.tmpNewMessages.length > 0) for (var i = 0; i < $scope.tmpNewMessages.length; i++) $scope.tmpNewMessages[i].position = i + 1;
                $scope.oldProfileMessages = angular.copy($scope.originalOldProfileMessages), $scope.tmpOldMessages = $scope.filterMessages($scope.oldProfileMessages), 
                null != $scope.token && 1 == $scope.uploaded && (CFTestPlanManager.deleteToken($scope.token), 
                $scope.token = null);
            }
        }, function(result) {});
    }, $scope.cancelToken = function() {
        $scope.error = null, $scope.executionError = [], null != $scope.token && CFTestPlanManager.deleteToken($scope.token).then(function(result) {
            $scope.token = null, $scope.testcase = null, $scope.profileMessages = null, $scope.originalProfileMessages = null, 
            $scope.originalOldProfileMessages = null, $scope.oldProfileMessages = null, $scope.existingTP = {
                selected: null
            }, $scope.selectedTP = {
                id: null
            }, $scope.profileValidationErrors = [], $scope.valueSetValidationErrors = [], $scope.constraintValidationErrors = [], 
            $scope.executionError = [], Notification.success({
                message: "Changes removed successfully!",
                templateUrl: "NotificationSuccessTemplate.html",
                scope: $rootScope,
                delay: 5e3
            }), $scope.afterSave($scope.token), $scope.token = null;
        }, function(error) {
            $scope.executionError = error.data, $scope.executionError.push(error.data);
        });
    }, $scope.deleteNewProfile = function(profile) {
        if (profile.removed = !0, $scope.tmpNewMessages = $scope.filterMessages($scope.profileMessages), 
        $scope.tmpNewMessages.length > 0) for (var i = 0; i < $scope.tmpNewMessages.length; i++) $scope.tmpNewMessages[i].position = i + 1;
    }, $scope.deleteOldProfile = function(profile) {
        profile.removed = !0, $scope.tmpOldMessages = $scope.filterMessages($scope.oldProfileMessages);
    }, $scope.getAddedProfiles = function() {
        return _.reject($scope.profileMessages, function(message) {
            return 1 == message.removed;
        });
    }, $scope.getRemovedProfiles = function() {
        return _.reject($scope.oldProfileMessages, function(message) {
            return void 0 == message.removed || 0 == message.removed;
        });
    }, $scope.getUpdatedProfiles = function() {
        return _.reject($scope.oldProfileMessages, function(message) {
            return 1 == message.removed;
        });
    }, $scope.treeOptions = {
        beforeDrop: function(e) {
            $scope.error = null;
            var sourceNode = e.source.nodeScope.$modelValue, destNode = e.dest.nodesScope.node, destPosition = e.dest.index + 1;
            return null != sourceNode && null != destNode && CFTestPlanManager.updateLocation(destNode, sourceNode, destPosition).then(function(result) {
                return "SUCCESS" == result.status || ($scope.error = "Failed to change profile group " + sourceNode.name + " position ", 
                !1);
            }, function(error) {
                return $scope.error = "Failed to change profile group " + sourceNode.name + " position ", 
                !1;
            });
        },
        dropped: function(e) {
            $scope.selectTestPlan();
        }
    }, $scope.openUploadModal = function() {
        $modalStack.dismissAll("close");
        var modalInstance = $modal.open({
            templateUrl: "views/cf/manage/upload.html",
            controller: "UploadCtrl",
            resolve: {
                isValidationOnly: function() {
                    return !1;
                }
            },
            scope: $scope,
            controllerAs: "ctrl",
            windowClass: "upload-modal",
            backdrop: "static",
            keyboard: !1
        });
        $scope.close = function(params) {
            modalInstance.close(params);
        }, $scope.dismissModal = function() {
            modalInstance.dismiss("cancel");
        }, modalInstance.result.then(function(result, profiles) {
            if (null != result.token) {
                $scope.token = result.token, $scope.uploaded = !0, $scope.originalProfileMessages = [], 
                $scope.profileMessages = [];
                for (var i = 0; i < result.profiles.length; i++) {
                    var profile = result.profiles[i];
                    $scope.profileMessages.push(profile);
                }
                if ($scope.tmpNewMessages = $scope.filterMessages($scope.profileMessages), $scope.tmpNewMessages.length > 0) for (var i = 0; i < $scope.tmpNewMessages.length; i++) $scope.tmpNewMessages[i].position = i + 1;
            }
        }, function(result) {});
    }, $scope.editExampleMessage = function(item) {
        $modalStack.dismissAll("close");
        var modalInstance = $modal.open({
            templateUrl: "views/cf/manage/message.html",
            controller: "CFManageExampleMessageCtrl",
            controllerAs: "ctrl",
            windowClass: "upload-modal",
            backdrop: "static",
            keyboard: !1,
            resolve: {
                exampleMessage: function() {
                    return item.exampleMessage;
                }
            }
        });
        modalInstance.result.then(function(exampleMessage) {
            item.exampleMessage = exampleMessage;
        }, function(result) {});
    };
} ]), angular.module("cf").controller("CFManageExampleMessageCtrl", function($scope, $http, $window, $modal, $filter, $rootScope, $timeout, StorageService, FileUploader, Notification, $modalInstance, exampleMessage) {
    $scope.exampleMessage = exampleMessage, $scope.save = function() {
        $modalInstance.close($scope.exampleMessage);
    }, $scope.cancel = function() {
        $modalInstance.dismiss();
    };
}), angular.module("cf").controller("UploadCtrl", [ "$scope", "$http", "$window", "$modal", "$filter", "$rootScope", "$timeout", "StorageService", "TestCaseService", "TestStepService", "FileUploader", "Notification", "userInfoService", "CFTestPlanManager", "isValidationOnly", function($scope, $http, $window, $modal, $filter, $rootScope, $timeout, StorageService, TestCaseService, TestStepService, FileUploader, Notification, userInfoService, CFTestPlanManager, isValidationOnly) {
    FileUploader.FileSelect.prototype.isEmptyAfterSelection = function() {
        return !0;
    }, $scope.step = 0, $scope.isValidationOnly = isValidationOnly, $scope.profileValidationErrors = [], 
    $scope.valueSetValidationErrors = [], $scope.constraintValidationErrors = [], $scope.profileUploadDone = !1, 
    $scope.vsUploadDone = !1, $scope.constraintsUploadDone = !1, $scope.validationReport = "", 
    $scope.executionError = [];
    var profileUploader = $scope.profileUploader = new FileUploader({
        url: "api/cf/hl7v2/management/uploadProfiles",
        autoUpload: !1,
        filters: [ {
            name: "xmlFilter",
            fn: function(item) {
                return /\/(xml)$/.test(item.type);
            }
        } ]
    }), vsUploader = $scope.vsUploader = new FileUploader({
        url: "api/cf/hl7v2/management/uploadValueSets",
        autoUpload: !1,
        filters: [ {
            name: "xmlFilter",
            fn: function(item) {
                return /\/(xml)$/.test(item.type);
            }
        } ]
    }), constraintsUploader = $scope.constraintsUploader = new FileUploader({
        url: "api/cf/hl7v2/management/uploadConstraints",
        autoUpload: !1,
        filters: [ {
            name: "xmlFilter",
            fn: function(item) {
                return /\/(xml)$/.test(item.type);
            }
        } ]
    }), valueSetBindingsUploader = $scope.valueSetBindingsUploader = new FileUploader({
        url: "api/cf/hl7v2/management/uploadValueSetBindings",
        autoUpload: !1,
        filters: [ {
            name: "xmlFilter",
            fn: function(item) {
                return /\/(xml)$/.test(item.type);
            }
        } ]
    }), coConstraintsUploader = $scope.coConstraintsUploader = new FileUploader({
        url: "api/cf/hl7v2/management/uploadCoConstraints",
        autoUpload: !1,
        filters: [ {
            name: "xmlFilter",
            fn: function(item) {
                return /\/(xml)$/.test(item.type);
            }
        } ]
    }), slicingsUploader = $scope.slicingsUploader = new FileUploader({
        url: "api/cf/hl7v2/management/uploadSlicings",
        autoUpload: !1,
        filters: [ {
            name: "xmlFilter",
            fn: function(item) {
                return /\/(xml)$/.test(item.type);
            }
        } ]
    }), zipUploader = $scope.zipUploader = new FileUploader({
        url: "api/cf/hl7v2/management/uploadZip",
        autoUpload: !0,
        filters: [ {
            name: "zipFilter",
            fn: function(item) {
                return /\/(zip)$/.test(item.type);
            }
        } ]
    });
    profileUploader.onErrorItem = function(fileItem, response, status, headers) {
        Notification.error({
            message: "There was an error while uploading " + fileItem.file.name,
            templateUrl: "NotificationErrorTemplate.html",
            scope: $rootScope,
            delay: 1e4
        }), $scope.step = 1;
    }, profileUploader.onCompleteItem = function(fileItem, response, status, headers) {
        0 == response.success ? ($scope.step = 1, $scope.executionError.push(response.debugError)) : ($scope.profileUploadDone = !0, 
        $scope.vsUploadDone === !0 && $scope.profileUploadDone === !0 && $scope.constraintsUploadDone === !0 && $scope.validatefiles($scope.token), 
        $scope.profileMessagesTmp = response.profiles);
    }, vsUploader.onCompleteItem = function(fileItem, response, status, headers) {
        0 == response.success ? ($scope.step = 1, $scope.executionError.push(response.debugError)) : ($scope.vsUploadDone = !0, 
        $scope.vsUploadDone === !0 && $scope.profileUploadDone === !0 && $scope.constraintsUploadDone === !0 && $scope.validatefiles($scope.token));
    }, constraintsUploader.onCompleteItem = function(fileItem, response, status, headers) {
        0 == response.success ? ($scope.step = 1, $scope.executionError.push(response.debugError)) : ($scope.constraintsUploadDone = !0, 
        $scope.vsUploadDone === !0 && $scope.profileUploadDone === !0 && $scope.constraintsUploadDone === !0 && $scope.validatefiles($scope.token));
    }, valueSetBindingsUploader.onCompleteItem = function(fileItem, response, status, headers) {
        0 == response.success ? ($scope.step = 1, $scope.executionError.push(response.debugError)) : $scope.valueSetBindingsUploadDone = !0;
    }, coConstraintsUploader.onCompleteItem = function(fileItem, response, status, headers) {
        0 == response.success ? ($scope.step = 1, $scope.executionError.push(response.debugError)) : $scope.coConstraintsUploadDone = !0;
    }, slicingsUploader.onCompleteItem = function(fileItem, response, status, headers) {
        0 == response.success ? ($scope.step = 1, $scope.executionError.push(response.debugError)) : $scope.slicingsUploadDone = !0;
    }, profileUploader.onBeforeUploadItem = function(fileItem) {
        $scope.profileValidationErrors = [], null == $scope.token && ($scope.token = $scope.generateUUID()), 
        fileItem.formData.push({
            token: $scope.token
        }), fileItem.formData.push({
            domain: $rootScope.domain.domain
        });
    }, constraintsUploader.onBeforeUploadItem = function(fileItem) {
        $scope.constraintValidationErrors = [], null == $scope.token && ($scope.token = $scope.generateUUID()), 
        fileItem.formData.push({
            token: $scope.token
        }), fileItem.formData.push({
            domain: $rootScope.domain.domain
        });
    }, vsUploader.onBeforeUploadItem = function(fileItem) {
        $scope.valueSetValidationErrors = [], null == $scope.token && ($scope.token = $scope.generateUUID()), 
        fileItem.formData.push({
            token: $scope.token
        }), fileItem.formData.push({
            domain: $rootScope.domain.domain
        });
    }, valueSetBindingsUploader.onBeforeUploadItem = function(fileItem) {
        $scope.valueSetBindingsValidationErrors = [], null == $scope.token && ($scope.token = $scope.generateUUID()), 
        fileItem.formData.push({
            token: $scope.token
        }), fileItem.formData.push({
            domain: $rootScope.domain.domain
        });
    }, coConstraintsUploader.onBeforeUploadItem = function(fileItem) {
        $scope.coConstraintsValidationErrors = [], null == $scope.token && ($scope.token = $scope.generateUUID()), 
        fileItem.formData.push({
            token: $scope.token
        }), fileItem.formData.push({
            domain: $rootScope.domain.domain
        });
    }, slicingsUploader.onBeforeUploadItem = function(fileItem) {
        $scope.slicingsValidationErrors = [], null == $scope.token && ($scope.token = $scope.generateUUID()), 
        fileItem.formData.push({
            token: $scope.token
        }), fileItem.formData.push({
            domain: $rootScope.domain.domain
        });
    }, zipUploader.onBeforeUploadItem = function(fileItem) {
        $scope.profileValidationErrors = [], $scope.valueSetValidationErrors = [], $scope.constraintValidationErrors = [], 
        $scope.validationReport = "", $scope.executionError = [], fileItem.formData.push({
            token: $scope.token
        }), fileItem.formData.push({
            domain: $rootScope.domain.domain
        });
    }, zipUploader.onCompleteItem = function(fileItem, response, status, headers) {
        $scope.isValidationOnly ? void 0 !== response.report ? ($scope.validationReport = response.report, 
        $scope.step = 1) : void 0 !== response.debugError && ($scope.executionError.push(response.debugError), 
        $scope.step = 1) : 0 == response.success ? void 0 === response.debugError ? (Notification.error({
            message: "The zip file you uploaded is not valid, please check and correct the error(s) and try again",
            templateUrl: "NotificationErrorTemplate.html",
            scope: $rootScope,
            delay: 1e4
        }), $scope.validationReport = response.report, $scope.step = 1) : ($scope.executionError.push(response.debugError), 
        $scope.step = 1) : ($scope.token = response.token, CFTestPlanManager.getTokenProfiles("hl7v2", $scope.token).then(function(response) {
            0 == response.success ? void 0 === response.debugError ? (Notification.error({
                message: "The zip file you uploaded is not valid, please check and correct the error(s)",
                templateUrl: "NotificationErrorTemplate.html",
                scope: $rootScope,
                delay: 1e4
            }), $scope.step = 1, $scope.validationReport = response.report) : (Notification.error({
                message: "  " + response.message + "<br>" + response.debugError,
                templateUrl: "NotificationErrorTemplate.html",
                scope: $rootScope,
                delay: 1e4
            }), $scope.step = 1) : ($scope.profileMessages = response.profiles, $scope.addSelectedTestCases());
        }, function(response) {}));
    }, $scope.gotStep = function(step) {
        $scope.step = step;
    }, profileUploader.onAfterAddingAll = function(fileItem) {
        profileUploader.queue.length > 1 && profileUploader.removeFromQueue(0);
    }, vsUploader.onAfterAddingAll = function(fileItem) {
        vsUploader.queue.length > 1 && vsUploader.removeFromQueue(0);
    }, constraintsUploader.onAfterAddingAll = function(fileItem) {
        constraintsUploader.queue.length > 1 && constraintsUploader.removeFromQueue(0);
    }, coConstraintsUploader.onAfterAddingAll = function(fileItem) {
        coConstraintsUploader.queue.length > 1 && coConstraintsUploader.removeFromQueue(0);
    }, slicingsUploader.onAfterAddingAll = function(fileItem) {
        slicingsUploader.queue.length > 1 && slicingsUploader.removeFromQueue(0);
    }, valueSetBindingsUploader.onAfterAddingAll = function(fileItem) {
        valueSetBindingsUploader.queue.length > 1 && valueSetBindingsUploader.removeFromQueue(0);
    }, $scope.getSelectedTestcases = function() {
        return $scope.profileMessages;
    }, $scope.validatefiles = function(token) {
        $scope.loading = !0, $http.get("api/cf/hl7v2/management/validate", {
            params: {
                token: token
            }
        }).then(function(response) {
            1 == response.data.success ? ($scope.profileMessages = $scope.profileMessagesTmp, 
            $scope.profileMessagesTmp = [], $scope.addSelectedTestCases()) : ($scope.profileMessagesTmp = [], 
            $scope.step = 1, response.data.report && ($scope.validationReport = response.data.report), 
            response.data.debugError && $scope.executionError.push(response.data.debugError)), 
            $scope.loading = !1;
        }, function(response) {
            $scope.profileMessagesTmp = [], $scope.step = 1, $scope.executionError.push(response.data.debugError), 
            $scope.loading = !1;
        });
    }, $scope.upload = function(value) {
        $scope.step = 0, $scope.token = $scope.generateUUID(), $scope.profileValidationErrors = [], 
        $scope.valueSetValidationErrors = [], $scope.constraintValidationErrors = [], $scope.valueSetBindingsValidationErrors = [], 
        $scope.coConstraintsValidationErrors = [], $scope.slicingsValidationErrors = [], 
        $scope.validationReport = "", $scope.executionError = [], $scope.profileUploadDone = !1, 
        $scope.vsUploadDone = !1, $scope.constraintsUploadDone = !1, $scope.valueSetBindingsUploadDone = !1, 
        $scope.coConstraintsUploadDone = !1, $scope.slicingsUploadDone = !1, vsUploader.uploadAll(), 
        constraintsUploader.uploadAll(), profileUploader.uploadAll(), valueSetBindingsUploader.uploadAll(), 
        coConstraintsUploader.uploadAll(), slicingsUploader.uploadAll();
    }, $scope.clear = function(value) {
        $scope.profileValidationErrors = [], $scope.valueSetValidationErrors = [], $scope.constraintValidationErrors = [], 
        $scope.valueSetBindingsValidationErrors = [], $scope.coConstraintsValidationErrors = [], 
        $scope.slicingsValidationErrors = [], $scope.validationReport = "", $scope.executionError = [], 
        $scope.profileUploadDone = !1, $scope.vsUploadDone = !1, $scope.constraintsUploadDone = !1, 
        $scope.valueSetBindingsUploadDone = !1, $scope.coConstraintsUploadDone = !1, $scope.slicingsUploadDone = !1, 
        profileUploader.clearQueue(), vsUploader.clearQueue(), constraintsUploader.clearQueue(), 
        valueSetBindingsUploader.clearQueue(), coConstraintsUploader.clearQueue(), slicingsUploader.clearQueue();
    }, $scope.addSelectedTestCases = function() {
        $scope.loading = !0, Notification.success({
            message: "Profile Added !",
            templateUrl: "NotificationSuccessTemplate.html",
            scope: $rootScope,
            delay: 5e3
        }), $scope.close({
            token: $scope.token,
            profiles: $scope.getSelectedTestcases()
        });
    }, $scope.getTotalProgress = function() {
        var numberOfactiveQueue = 0, progress = 0;
        return profileUploader.queue.length > 0 && (numberOfactiveQueue++, progress += profileUploader.progress), 
        vsUploader.queue.length > 0 && (numberOfactiveQueue++, progress += vsUploader.progress), 
        constraintsUploader.queue.length > 0 && (numberOfactiveQueue++, progress += constraintsUploader.progress), 
        valueSetBindingsUploader.queue.length > 0 && (numberOfactiveQueue++, progress += valueSetBindingsUploader.progress), 
        coConstraintsUploader.queue.length > 0 && (numberOfactiveQueue++, progress += coConstraintsUploader.progress), 
        slicingsUploader.queue.length > 0 && (numberOfactiveQueue++, progress += slicingsUploader.progress), 
        progress / numberOfactiveQueue;
    }, $scope.generateUUID = function() {
        var d = new Date().getTime(), uuid = "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, function(c) {
            var r = (d + 16 * Math.random()) % 16 | 0;
            return d = Math.floor(d / 16), ("x" == c ? r : 3 & r | 8).toString(16);
        });
        return uuid;
    };
} ]), angular.module("cf").controller("UploadTokenCheckCtrl", [ "$scope", "$http", "CF", "$window", "$modal", "$filter", "$rootScope", "$timeout", "StorageService", "TestCaseService", "TestStepService", "userInfoService", "Notification", "modalService", "$routeParams", "$location", function($scope, $http, CF, $window, $modal, $filter, $rootScope, $timeout, StorageService, TestCaseService, TestStepService, userInfoService, Notification, modalService, $routeParams, $location) {
    $scope.testcase = {}, $scope.profileValidationErrors = [], $scope.valueSetValidationErrors = [], 
    $scope.constraintValidationErrors = [], $scope.profileCheckToggleStatus = !1, $scope.token = decodeURIComponent($routeParams.x), 
    $scope.auth = decodeURIComponent($routeParams.y), $scope.domain = decodeURIComponent($routeParams.d), 
    void 0 !== $scope.token && void 0 !== $scope.auth && (userInfoService.isAuthenticated() ? ($rootScope.appLoad(), 
    $rootScope.setDomain($scope.domain), $location.url("/addprofiles?x=" + $scope.token + "&d=" + $scope.domain)) : $scope.$emit("event:loginRequestWithAuth", $scope.auth, "/addprofiles?x=" + $scope.token + "&d=" + $scope.domain, !0));
} ]), angular.module("cf").controller("CreateTestPlanCtrl", function($scope, $modalInstance, scope, CFTestPlanManager, position, domain) {
    $scope.newGroup = {
        name: null,
        description: null,
        scope: scope,
        domain: domain,
        position: position
    }, $scope.error = null, $scope.loading = !1, $scope.submit = function() {
        null != $scope.newGroup.name && "" != $scope.newGroup.name && null != $scope.newGroup.domain && "" != $scope.newGroup.domain && ($scope.error = null, 
        $scope.loading = !0, CFTestPlanManager.createTestPlan($scope.newGroup).then(function(testPlan) {
            $scope.loading = !1, $modalInstance.close(testPlan);
        }, function(error) {
            $scope.loading = !1, $scope.error = "Sorry, Cannot create a new profile group. Please try again";
        }));
    }, $scope.cancel = function() {
        $modalInstance.dismiss("cancel");
    };
}), angular.module("cf").controller("CreateTestStepGroupCtrl", function($scope, $modalInstance, scope, CFTestPlanManager, position, domain, parentNode) {
    $scope.newGroup = {
        name: null,
        description: null,
        scope: scope,
        domain: domain,
        position: position
    }, $scope.error = null, $scope.loading = !1, $scope.submit = function() {
        null != $scope.newGroup.name && "" != $scope.newGroup.name && null != $scope.newGroup.domain && "" != $scope.newGroup.domain && ($scope.error = null, 
        $scope.loading = !0, CFTestPlanManager.addChild($scope.newGroup, parentNode).then(function(group) {
            $scope.loading = !1, $modalInstance.close(group);
        }, function(error) {
            $scope.error = "Sorry, Cannot create a new profile group. Please try again";
        }));
    }, $scope.cancel = function() {
        $modalInstance.dismiss("cancel");
    };
}), angular.module("cb").controller("CBTestingCtrl", [ "$scope", "$window", "$rootScope", "CB", "StorageService", "$timeout", "TestCaseService", "TestStepService", "$routeParams", "userInfoService", function($scope, $window, $rootScope, CB, StorageService, $timeout, TestCaseService, TestStepService, $routeParams, userInfoService) {
    $scope.cb = CB, $scope.testCase = null, $scope.token = $routeParams.x, $scope.domain = $routeParams.d, 
    $scope.initTesting = function() {
        if (void 0 !== $routeParams.scope && void 0 !== $routeParams.group) StorageService.set(StorageService.CB_SELECTED_TESTPLAN_ID_KEY, $routeParams.group), 
        StorageService.set(StorageService.CB_SELECTED_TESTPLAN_SCOPE_KEY, $routeParams.scope), 
        $scope.setSubActive("/cb_testcase", $routeParams.scope, $routeParams.group); else {
            var tab = StorageService.get(StorageService.ACTIVE_SUB_TAB_KEY);
            (null == tab || "/cb_execution" !== tab && "/cb_management" !== tab) && (tab = "/cb_testcase"), 
            $scope.setSubActive(tab);
        }
        $scope.$on("cb:testCaseLoaded", function(event, testCase, tab) {
            $scope.testCase = testCase;
        });
    }, $scope.setSubActive = function(tab, scope, group) {
        $rootScope.setSubActive(tab), $timeout(function() {
            "/cb_execution" === tab ? ($scope.$broadcast("cb:refreshEditor"), $rootScope.$broadcast("event:refreshLoadedTestCase")) : "/cb_testcase" === tab ? void 0 !== scope && void 0 !== group ? $scope.$broadcast("event:cb:initTestCase", {
                scope: scope,
                group: group
            }) : $scope.$broadcast("event:cb:initTestCase") : "/cb_management" === tab && $scope.$broadcast("event:cb:initManagement");
        }, 500);
    };
} ]), angular.module("cb").controller("CBExecutionCtrl", [ "$scope", "$window", "$rootScope", "CB", "$modal", "TestExecutionClock", "Endpoint", "TestExecutionService", "$timeout", "StorageService", "User", "ReportService", "TestCaseDetailsService", "$compile", "Transport", "$filter", "SOAPEscaper", "Notification", function($scope, $window, $rootScope, CB, $modal, TestExecutionClock, Endpoint, TestExecutionService, $timeout, StorageService, User, ReportService, TestCaseDetailsService, $compile, Transport, $filter, SOAPEscaper, Notification) {
    $scope.cb = CB, $scope.targ = "cb-executed-test-step", $scope.loading = !1, $scope.error = null, 
    $scope.tabs = new Array(), $scope.testCase = null, $scope.testStep = null, $scope.logger = CB.logger, 
    $scope.connecting = !1, $scope.transport = Transport, $scope.endpoint = null, $scope.hidePwd = !0, 
    $scope.sent = null, $scope.received = null, $scope.configCollapsed = !0, $scope.counterMax = $scope.transport.getTimeout(), 
    $scope.counter = 0, $scope.listenerReady = !1, $scope.testStepListCollapsed = !1, 
    $scope.warning = null, $scope.sutInititiatorForm = "", $scope.taInititiatorForm = "", 
    $scope.user = User, $scope.domain = null, $scope.protocol = null != StorageService.get(StorageService.TRANSPORT_PROTOCOL) && void 0 != StorageService.get(StorageService.TRANSPORT_PROTOCOL) ? StorageService.get(StorageService.TRANSPORT_PROTOCOL) : null, 
    $scope.exampleMessageEditor = null, $scope.testExecutionService = TestExecutionService, 
    $scope.loadingExecution = !1, $scope.saveButtonText = "Save Test Case Report", $scope.initExecution = function() {
        $scope.$on("cb:testCaseLoaded", function(event, testCase, tab) {
            $scope.executeTestCase(testCase, tab);
        });
    };
    var errors = [ "Incorrect message Received. Please check the log for more details", "No Outbound message found", "Invalid message Received. Please see console for more details.", "Invalid message Sent. Please see console for more details." ], parseRequest = function(incoming) {
        return incoming;
    }, parseResponse = function(outbound) {
        return outbound;
    };
    $scope.setTestStepExecutionTab = function(value) {
        $scope.tabs[0] = !1, $scope.tabs[1] = !1, $scope.tabs[2] = !1, $scope.tabs[3] = !1, 
        $scope.tabs[4] = !1, $scope.tabs[5] = !1, $scope.tabs[6] = !1, $scope.tabs[7] = !1, 
        $scope.tabs[8] = !1, $scope.tabs[9] = !1, $scope.activeTab = value, $scope.tabs[$scope.activeTab] = !0, 
        5 === $scope.activeTab ? $scope.buildExampleMessageEditor() : 6 === $scope.activeTab ? $scope.loadArtifactHtml("jurorDocument") : 7 === $scope.activeTab ? $scope.loadArtifactHtml("messageContent") : 8 === $scope.activeTab ? $scope.loadArtifactHtml("testDataSpecification") : 9 === $scope.activeTab && $scope.loadArtifactHtml("testStory");
    }, $scope.isTestCase = function() {
        return null != CB.testCase && "TestCase" === CB.testCase.type;
    }, $scope.getTestType = function() {
        return CB.testCase.type;
    }, $scope.disabled = function() {
        return null == CB.testCase || null === CB.testCase.id;
    }, $scope.getTestType = function() {
        return null != $scope.testCase ? $scope.testCase.type : "";
    }, $scope.loadTestStepDetails = function(testStep) {
        var tsId = $scope.targ + "-testStory", jDocId = $scope.targ + "-jurorDocument", mcId = $scope.targ + "-messageContent", tdsId = $scope.targ + "-testDataSpecification";
        TestCaseDetailsService.removeHtml(tdsId), TestCaseDetailsService.removeHtml(mcId), 
        TestCaseDetailsService.removeHtml(jDocId), TestCaseDetailsService.removeHtml(tsId), 
        $scope.$broadcast(tsId, testStep.testStory, testStep.name + "-TestStory"), $scope.$broadcast(jDocId, testStep.jurorDocument, testStep.name + "-JurorDocument"), 
        $scope.$broadcast(mcId, testStep.messageContent, testStep.name + "-MessageContent"), 
        $scope.$broadcast(tdsId, testStep.testDataSpecification, testStep.name + "-TestDataSpecification"), 
        $scope.isManualStep(testStep) && $scope.setTestStepExecutionTab(1);
    }, $scope.loadTestStepExecutionPanel = function(testStep) {
        $scope.exampleMessageEditor = null, $scope.detailsError = null;
        var testContext = testStep.testContext;
        if (testContext && null != testContext) {
            $scope.setTestStepExecutionTab(0), $scope.$broadcast("cb:testStepLoaded", testStep), 
            $scope.$broadcast("cb:profileLoaded", testContext.profile), $scope.$broadcast("cb:valueSetLibraryLoaded", testContext.vocabularyLibrary), 
            TestCaseDetailsService.removeHtml($scope.targ + "-exampleMessage");
            var exampleMessage = testContext.message && testContext.message.content && null != testContext.message.content ? testContext.message.content : null;
            null != exampleMessage && $scope.$broadcast($scope.targ + "-exampleMessage", exampleMessage, testContext.format, testStep.name);
        } else {
            $scope.setTestStepExecutionTab(1);
            var result = TestExecutionService.getTestStepValidationReport(testStep);
            $rootScope.$emit("cbManual:updateTestStepValidationReport", void 0 != result && null != result ? result.reportId : null, testStep, $scope.isTestCase());
        }
        $scope.targ + "-exampleMessage";
        TestCaseDetailsService.details("cb", "TestStep", testStep.id).then(function(result) {
            testStep.testStory = result.testStory, testStep.jurorDocument = result.jurorDocument, 
            testStep.testDataSpecification = result.testDataSpecification, testStep.messageContent = result.messageContent, 
            $scope.loadTestStepDetails(testStep), $scope.detailsError = null;
        }, function(error) {
            testStep.testStory = null, testStep.testPackage = null, testStep.jurorDocument = null, 
            testStep.testDataSpecification = null, testStep.messageContent = null, $scope.loadTestStepDetails(testStep), 
            $scope.detailsError = "Sorry, could not load the test step details. Please try again";
        });
    }, $scope.buildExampleMessageEditor = function() {
        var eId = $scope.targ + "-exampleMessage";
        null !== $scope.exampleMessageEditor && $scope.exampleMessageEditor || $timeout(function() {
            $scope.exampleMessageEditor = TestCaseDetailsService.buildExampleMessageEditor(eId, $scope.testStep.testContext.message.content, $scope.exampleMessageEditor, $scope.testStep.testContext && null != $scope.testStep.testContext ? $scope.testStep.testContext.format : null);
        }, 100), $timeout(function() {
            $("#" + eId) && $("#" + eId).scrollLeft();
        }, 1e3);
    }, $scope.loadArtifactHtml = function(key) {
        if (null != $scope.testStep) {
            var element = TestCaseDetailsService.loadArtifactHtml($scope.targ + "-" + key, $scope.testStep[key]);
            element && null != element && $compile(element.contents())($scope);
        }
    }, $scope.resetTestCase = function() {
        null != $scope.testCase && ($scope.loadingExecution = !0, $scope.error = null, TestExecutionService.clear($scope.testCase.id).then(function(res) {
            $scope.loadingExecution = !1, $scope.error = null, null != CB.editor && null != CB.editor.instance && CB.editor.instance.setOption("readOnly", !1), 
            StorageService.remove(StorageService.CB_LOADED_TESTSTEP_TYPE_KEY), StorageService.remove(StorageService.CB_LOADED_TESTSTEP_ID_KEY), 
            $scope.executeTestCase($scope.testCase);
        }, function(error) {
            $scope.loadingExecution = !1, $scope.error = null;
        }));
    }, $scope.selectProtocol = function(testStep) {
        null != testStep && ($scope.protocol = testStep.protocol, StorageService.set(StorageService.TRANSPORT_PROTOCOL, $scope.protocol));
    }, $scope.selectTestStep = function(testStep) {
        if (CB.testStep = testStep, $scope.testStep = testStep, null != testStep) if (StorageService.set(StorageService.CB_LOADED_TESTSTEP_TYPE_KEY, $scope.testStep.type), 
        StorageService.set(StorageService.CB_LOADED_TESTSTEP_ID_KEY, $scope.testStep.id), 
        $scope.isManualStep(testStep)) $scope.loadTestStepExecutionPanel(testStep); else if (void 0 === $scope.testExecutionService.getTestStepExecutionMessage(testStep) && "TA_INITIATOR" === testStep.testingType) if ($scope.transport.disabled || null == $scope.domain || null == $scope.protocol) {
            var con = $scope.testExecutionService.getTestStepExecutionMessage(testStep);
            con = null != con && void 0 != con ? con : testStep.testContext.message.content, 
            $scope.testExecutionService.setTestStepExecutionMessage(testStep, con), $scope.loadTestStepExecutionPanel(testStep);
        } else {
            var populateMessage = $scope.transport.populateMessage(testStep.id, testStep.testContext.message.content, $scope.domain, $scope.protocol);
            populateMessage.then(function(response) {
                $scope.testExecutionService.setTestStepExecutionMessage(testStep, response.outgoingMessage), 
                $scope.loadTestStepExecutionPanel(testStep);
            }, function(error) {
                $scope.testExecutionService.setTestStepExecutionMessage(testStep, testStep.testContext.message.content), 
                $scope.loadTestStepExecutionPanel(testStep);
            });
        } else void 0 === $scope.testExecutionService.getTestStepExecutionMessage(testStep) && "TA_RESPONDER" === testStep.testingType && $scope.transport.disabled ? ($scope.testExecutionService.setTestStepExecutionMessage(testStep, testStep.testContext.message.content), 
        $scope.loadTestStepExecutionPanel(testStep)) : $scope.loadTestStepExecutionPanel(testStep);
    }, $scope.viewTestStepResult = function(testStep) {
        CB.testStep = testStep, $scope.testStep = testStep, null != testStep && (StorageService.set(StorageService.CB_LOADED_TESTSTEP_TYPE_KEY, $scope.testStep.type), 
        StorageService.set(StorageService.CB_LOADED_TESTSTEP_ID_KEY, $scope.testStep.id), 
        $scope.loadTestStepExecutionPanel(testStep));
    }, $scope.clearTestStep = function() {
        CB.testStep = null, $scope.testStep = null, $scope.$broadcast("cb:removeTestStep");
    }, $scope.getTestStepExecutionStatus = function(testStep) {
        return $scope.testExecutionService.getTestStepExecutionStatus(testStep);
    }, $scope.getTestStepValidationResult = function(testStep) {
        return $scope.testExecutionService.getTestStepValidationResult(testStep);
    }, $scope.getTestStepValidationReport = function(testStep) {
        return $scope.testExecutionService.getTestStepValidationReport(testStep);
    }, $scope.getManualValidationStatusTitle = function(testStep) {
        return $scope.testExecutionService.getManualValidationStatusTitle(testStep);
    }, $scope.isManualStep = function(testStep) {
        return null != testStep && ("TA_MANUAL" === testStep.testingType || "SUT_MANUAL" === testStep.testingType);
    }, $scope.isSutInitiator = function(testStep) {
        return "SUT_INITIATOR" == testStep.testingType;
    }, $scope.isTaInitiator = function(testStep) {
        return "TA_INITIATOR" == testStep.testingType;
    }, $scope.isTestStepCompleted = function(testStep) {
        return "COMPLETE" === $scope.testExecutionService.getTestStepExecutionStatus(testStep);
    }, $scope.completeStep = function(row) {
        $scope.testExecutionService.setTestStepExecutionStatus(row, "COMPLETE");
    }, $scope.completeManualStep = function(row) {
        $scope.completeStep(row);
    }, $scope.progressStep = function(row) {
        $scope.testExecutionService.setTestStepExecutionStatus(row, "IN_PROGRESS");
    }, $scope.goNext = function(row) {
        null != row && row && ($scope.isLastStep(row) ? $scope.completeTestCase() : $scope.executeTestStep($scope.findNextStep(row.position)));
    }, $scope.goBack = function(row) {
        null != row && row && ($scope.isFirstStep(row) || $scope.executeTestStep($scope.findPreviousStep(row.position)));
    }, $scope.executeTestStep = function(testStep) {
        if (null != testStep && void 0 != testStep) {
            if ($scope.testExecutionService.testStepCommentsChanged[testStep.id] = !1, TestExecutionService.setTestStepValidationReport(testStep, null), 
            CB.testStep = testStep, $scope.warning = null, ($scope.isManualStep(testStep) || "TA_RESPONDER" === testStep.testingType) && $scope.completeStep(testStep), 
            testStep.protocol = null, $scope.protocol = null, null != testStep.protocols && testStep.protocols && testStep.protocols.length > 0) {
                var protocol = null != StorageService.get(StorageService.TRANSPORT_PROTOCOL) && void 0 != StorageService.get(StorageService.TRANSPORT_PROTOCOL) ? StorageService.get(StorageService.TRANSPORT_PROTOCOL) : null;
                protocol = null != protocol && testStep.protocols.indexOf(protocol) > 0 ? protocol : null, 
                protocol = null != protocol ? protocol : $scope.getDefaultProtocol(testStep), testStep.protocol = protocol, 
                $scope.selectProtocol(testStep);
            }
            var log = $scope.transport.logs[testStep.id];
            $scope.logger.content = log && null != log ? log : "", $scope.selectTestStep(testStep);
        }
    }, $scope.getDefaultProtocol = function(testStep) {
        if (null != testStep.protocols && testStep.protocols && testStep.protocols.length > 0) {
            testStep.protocols = $filter("orderBy")(testStep.protocols, "position");
            for (var i = 0; i < testStep.protocols.length; i++) if (void 0 != testStep.protocols[i].defaut && testStep.protocols[i].defaut === !0) return testStep.protocols[i].value;
            return testStep.protocols[0].value;
        }
        return null;
    }, $scope.completeTestCase = function() {
        StorageService.remove(StorageService.CB_LOADED_TESTSTEP_ID_KEY), $scope.testExecutionService.setTestCaseExecutionStatus($scope.testCase, "COMPLETE"), 
        null != CB.editor.instance && CB.editor.instance.setOption("readOnly", !0), TestExecutionService.setTestCaseValidationResultFromTestSteps($scope.testCase), 
        $scope.clearTestStep(), $scope.selectTestStep(null);
    }, $scope.isTestCaseCompleted = function() {
        return "COMPLETE" === $scope.testExecutionService.getTestCaseExecutionStatus($scope.testCase);
    }, $scope.shouldNextStep = function(row) {
        return null != $scope.testStep && $scope.testStep === row && !$scope.isTestCaseCompleted() && !$scope.isLastStep(row) && $scope.isTestStepCompleted(row);
    }, $scope.isLastStep = function(row) {
        return row && null != row && null != $scope.testCase && $scope.testCase.children.length === row.position;
    }, $scope.isFirstStep = function(row) {
        return row && null != row && null != $scope.testCase && 1 === row.position;
    }, $scope.isTestCaseSuccessful = function() {
        var status = $scope.testExecutionService.getTestCaseValidationResult($scope.testCase);
        return "PASSED" === status;
    }, $scope.isTestStepValidated = function(testStep) {
        return void 0 != $scope.testExecutionService.getTestStepValidationResult(testStep);
    }, $scope.isTestStepSuccessful = function(testStep) {
        $scope.testExecutionService.getTestStepValidationResult(testStep);
        return !0;
    }, $scope.findNextStep = function(position) {
        for (var i = 0; i < $scope.testCase.children.length; i++) if ($scope.testCase.children[i].position === position + 1) return $scope.testCase.children[i];
        return null;
    }, $scope.findPreviousStep = function(position) {
        for (var i = 0; i < $scope.testCase.children.length; i++) if ($scope.testCase.children[i].position === position - 1) return $scope.testCase.children[i];
        return null;
    }, $scope.clearExecution = function() {
        null != CB.editor && null != CB.editor.instance && CB.editor.instance.setOption("readOnly", !1), 
        $scope.loadingExecution = !0, $scope.error = null, TestExecutionService.clear($scope.testCase).then(function(res) {
            $scope.loadingExecution = !1, $scope.error = null;
        }, function(error) {
            $scope.loadingExecution = !1, $scope.error = null;
        });
    }, $scope.setNextStepMessage = function(message) {
        var nextStep = $scope.findNextStep($scope.testStep.position);
        null == nextStep || $scope.isManualStep(nextStep) || ($scope.completeStep(nextStep), 
        $scope.testExecutionService.setTestStepExecutionMessage(nextStep, message));
    }, $scope.log = function(log) {
        $scope.logger.log(log);
    }, $scope.isValidConfig = function() {}, $scope.outboundMessage = function() {
        return null != $scope.testStep ? $scope.testStep.testContext.message.content : null;
    }, $scope.hasUserContent = function() {
        return CB.editor && null != CB.editor && null != CB.editor.instance.doc.getValue() && "" != CB.editor.instance.doc.getValue();
    }, $scope.hasRequestContent = function() {
        return null != $scope.outboundMessage() && "" != $scope.outboundMessage();
    }, $scope.saveTransportLog = function() {
        $timeout(function() {
            $scope.transport.saveTransportLog($scope.testStep.id, $scope.logger.content, $scope.domain, $scope.protocol);
        });
    }, $scope.send = function() {
        $scope.connecting = !0, $scope.openConsole($scope.testStep), $scope.logger.clear(), 
        $scope.progressStep($scope.testStep), $scope.error = null, $scope.hasUserContent() ? ($scope.received = "", 
        $scope.logger.log("Sending outbound Message. Please wait..."), $scope.transport.send($scope.testStep.id, CB.editor.instance.doc.getValue(), $scope.domain, $scope.protocol).then(function(response) {
            var received = response.incoming, sent = response.outgoing;
            if ($scope.logger.log("Outbound Message  -------------------------------------->"), 
            null != sent && "" != sent) if ($scope.logger.log(sent), $scope.logger.log("Inbound Message  <--------------------------------------"), 
            null != received && "" != received) try {
                $scope.completeStep($scope.testStep);
                var rspMessage = parseResponse(received);
                $scope.logger.log(received);
                var nextStep = $scope.findNextStep($scope.testStep.position);
                null != nextStep && "SUT_RESPONDER" === nextStep.testingType && $scope.setNextStepMessage(rspMessage);
            } catch (error) {
                $scope.error = errors[0], $scope.logger.log("An error occured: " + $scope.error);
            } else $scope.logger.log("No Inbound message received"); else $scope.logger.log("No outbound message sent");
            $scope.connecting = !1, $scope.transport.logs[$scope.testStep.id] = $scope.logger.content, 
            $scope.logger.log("Transaction completed"), $scope.saveTransportLog();
        }, function(error) {
            $scope.connecting = !1, $scope.error = error.data, $scope.logger.log("Error: " + error.data), 
            $scope.received = "", $scope.completeStep($scope.testStep), $scope.transport.logs[$scope.testStep.id] = $scope.logger.content, 
            $scope.logger.log("Transaction stopped"), $scope.saveTransportLog();
        })) : ($scope.error = "No message to send", $scope.connecting = !1, $scope.transport.logs[$scope.testStep.id] = $scope.logger.content, 
        $scope.logger.log("Transaction completed"), $scope.saveTransportLog());
    }, $scope.viewConsole = function(testStep) {
        $scope.consoleDlg && null !== $scope.consoleDlg && $scope.consoleDlg.opened && $scope.consoleDlg.dismiss("cancel"), 
        $scope.consoleDlg = $modal.open({
            templateUrl: "PastTestStepConsole.html",
            controller: "PastTestStepConsoleCtrl",
            windowClass: "console-modal",
            size: "sm",
            animation: !0,
            keyboard: !0,
            backdrop: !0,
            resolve: {
                log: function() {
                    return $scope.transport.logs[testStep.id];
                },
                title: function() {
                    return testStep.name;
                }
            }
        });
    }, $scope.openConsole = function(testStep) {
        $scope.consoleDlg && null !== $scope.consoleDlg && $scope.consoleDlg.opened && $scope.consoleDlg.dismiss("cancel"), 
        $scope.consoleDlg = $modal.open({
            templateUrl: "CurrentTestStepConsole.html",
            controller: "CurrentTestStepConsoleCtrl",
            windowClass: "console-modal",
            size: "lg",
            animation: !0,
            keyboard: !0,
            backdrop: !0,
            resolve: {
                logger: function() {
                    return $scope.logger;
                },
                title: function() {
                    return testStep.name;
                }
            }
        });
    }, $scope.stopListener = function() {
        $scope.connecting = !1, $scope.counter = $scope.counterMax, TestExecutionClock.stop(), 
        $scope.logger.log("Stopping listener. Please wait...."), $scope.transport.stopListener($scope.testStep.id, $scope.domain, $scope.protocol).then(function(response) {
            $scope.logger.log("Listener stopped."), $scope.transport.logs[$scope.testStep.id] = $scope.logger.content, 
            $scope.saveTransportLog();
        }, function(error) {
            $scope.saveTransportLog();
        });
    }, $scope.updateTestStepValidationReport = function(testStep) {
        if ($scope.saveButtonDisabled = !1, $scope.saveButtonText = "Save Test Case Report", 
        StorageService.set("testStepValidationResults", angular.toJson(TestExecutionService.testStepValidationResults)), 
        StorageService.set("testStepComments", angular.toJson(TestExecutionService.testStepComments)), 
        null === $scope.testStep || testStep.id !== $scope.testStep.id) TestExecutionService.updateTestStepValidationReport(testStep); else {
            var reportType = testStep.testContext && null != testStep.testContext ? "cbValidation" : "cbManual", result = TestExecutionService.getTestStepValidationReport(testStep);
            $rootScope.$emit(reportType + ":updateTestStepValidationReport", result && null != result ? result : null, testStep, $scope.getTestType());
        }
    }, $scope.abortListening = function() {
        $scope.testExecutionService.deleteTestStepExecutionStatus($scope.testStep), $scope.stopListener();
    }, $scope.completeListening = function() {
        $scope.completeStep($scope.testStep), $scope.stopListener();
    }, $scope.setTimeout = function(value) {
        $scope.transport.setTimeout(value), $scope.counterMax = value;
    }, $scope.startListener = function() {
        $scope.openConsole($scope.testStep);
        var nextStep = $scope.findNextStep($scope.testStep.position);
        if (null != nextStep) {
            var rspMessageId = nextStep.testContext.message.id;
            $scope.configCollapsed = !1, $scope.logger.clear(), $scope.counter = 0, $scope.connecting = !0, 
            $scope.error = null, $scope.warning = null, $scope.progressStep($scope.testStep), 
            $scope.logger.log("Starting listener. Please wait..."), $scope.transport.startListener($scope.testStep.id, rspMessageId, $scope.domain, $scope.protocol).then(function(started) {
                if (started) {
                    $scope.logger.log("Listener started.");
                    var execute = function() {
                        var remaining = parseInt($scope.counterMax) - parseInt($scope.counter);
                        remaining % 20 === 0 && $scope.logger.log("Waiting for Inbound Message....Remaining time:" + remaining + "s"), 
                        ++$scope.counter;
                        var sutInitiator = null;
                        try {
                            sutInitiator = $scope.transport.configs[$scope.protocol].data.sutInitiator;
                        } catch (e) {
                            sutInitiator = null;
                        }
                        $scope.transport.searchTransaction($scope.testStep.id, sutInitiator, rspMessageId, $scope.domain, $scope.protocol).then(function(transaction) {
                            if (null != transaction) {
                                var incoming = transaction.incoming, outbound = transaction.outgoing;
                                if ($scope.logger.log("Inbound message received <-------------------------------------- "), 
                                null != incoming && "" != incoming) try {
                                    var receivedMessage = parseRequest(incoming);
                                    $scope.log(receivedMessage), $scope.testExecutionService.setTestStepExecutionMessage($scope.testStep, receivedMessage), 
                                    $scope.$broadcast("cb:loadEditorContent", receivedMessage);
                                } catch (error) {
                                    $scope.error = errors[2], $scope.logger.log("Incorrect Inbound message type");
                                } else $scope.logger.log("Incoming message received is empty");
                                if ($scope.logger.log("Outbound message sent --------------------------------------> "), 
                                null != outbound && "" != outbound) try {
                                    var sentMessage = parseResponse(outbound);
                                    $scope.log(sentMessage);
                                    var nextStep = $scope.findNextStep($scope.testStep.position);
                                    null != nextStep && "TA_RESPONDER" === nextStep.testingType && $scope.setNextStepMessage(sentMessage);
                                } catch (error) {
                                    $scope.error = errors[3], $scope.logger.log("Incorrect outgoing message type");
                                } else $scope.logger.log("Outbound message sent is empty");
                                $scope.completeListening();
                            } else $scope.counter >= $scope.counterMax && ($scope.warning = "We did not receive any incoming message after 2 min. <p>Possible cause (1): You are using wrong credentials. Please check the credentials in your outbound message against those created for your system.</p>  <p>Possible cause (2):The endpoint address may be incorrect.   Verify that you are using the correct endpoint address that is displayed by the tool.</p>", 
                            $scope.abortListening());
                        }, function(error) {
                            $scope.error = error, $scope.log("Error: " + error), $scope.received = "", $scope.sent = "", 
                            $scope.abortListening();
                        });
                    };
                    TestExecutionClock.start(execute);
                } else $scope.logger.log("Failed to start listener"), $scope.logger.log("Transaction stopped"), 
                $scope.connecting = !1, $scope.error = "Failed to start the listener. Please contact the administrator.", 
                TestExecutionClock.stop();
            }, function(error) {
                $scope.connecting = !1, $scope.counter = $scope.counterMax, $scope.error = "Failed to start the listener. Error: " + error, 
                $scope.logger.log($scope.error), $scope.logger.log("Transaction stopped"), TestExecutionClock.stop();
            });
        }
    }, $scope.downloadJurorDoc = function(jurorDocId, title) {
        var content = $("#" + jurorDocId).html();
        if (content && "" != content) {
            var form = document.createElement("form");
            form.action = "api/artifact/generateJurorDoc/pdf", form.method = "POST", form.target = "_target";
            var input = document.createElement("textarea");
            input.name = "html", input.value = content, form.appendChild(input);
            var type = document.createElement("input");
            type.name = "type", type.value = "JurorDocument", form.style.display = "none", form.appendChild(type);
            var nam = document.createElement("input");
            nam.name = "type", nam.value = title, form.style.display = "none", form.appendChild(nam), 
            document.body.appendChild(form), form.submit();
        }
    }, $scope.downloadTestArtifact = function(path) {
        if (null != $scope.testCase) {
            var form = document.createElement("form");
            form.action = "api/artifact/download", form.method = "POST", form.target = "_target";
            var input = document.createElement("input");
            input.name = "path", input.value = path, form.appendChild(input), form.style.display = "none", 
            document.body.appendChild(form), form.submit();
        }
    }, $scope.executeTestCase = function(testCase, tab) {
        if (null != testCase) {
            if ($scope.loading = !0, TestExecutionService.init(), CB.testStep = null, $scope.testStep = null, 
            $scope.setTestStepExecutionTab(0), tab = tab && null != tab ? tab : "/cb_execution", 
            $rootScope.setSubActive(tab), "/cb_execution" === tab && $scope.$broadcast("cb:refreshEditor"), 
            $scope.logger.clear(), $scope.error = null, $scope.warning = null, $scope.connecting = !1, 
            $scope.domain = testCase.domain, CB.testCase = testCase, $scope.transport.logs = {}, 
            $scope.transport.transactions = [], $scope.testCase = testCase, TestExecutionClock.stop(), 
            null != CB.editor && null != CB.editor.instance && CB.editor.instance.setOption("readOnly", !1), 
            "TestCase" === testCase.type) {
                var testStepId = StorageService.get(StorageService.CB_LOADED_TESTSTEP_ID_KEY), testStep = $scope.findTestStepById(testStepId);
                testStep = null != testStep ? testStep : $scope.testCase.children[0], $scope.executeTestStep(testStep);
            } else "TestStep" === testCase.type && $scope.executeTestStep(testCase);
            $scope.loading = !1;
        }
    }, $scope.findTestStepById = function(testStepId) {
        if (null != testStepId && void 0 != testStepId) for (var i = 0; i < $scope.testCase.children.length; i++) if ($scope.testCase.children[i].id === testStepId) return $scope.testCase.children[i];
        return null;
    }, $scope.exportAs = function(format) {
        if (null != $scope.testCase) {
            var result = TestExecutionService.getTestCaseValidationResult($scope.testCase);
            result = void 0 != result ? result : null;
            var comments = TestExecutionService.getTestCaseComments($scope.testCase);
            comments = void 0 != comments ? comments : null, ReportService.downloadTestCaseReports($scope.testCase.id, format, result, comments, $scope.testCase.nav.testPlan, $scope.testCase.nav.testGroup);
        }
    }, $scope.isReportSavingSupported = function() {
        return $rootScope.isReportSavingSupported();
    }, $scope.isNotAllManualTest = function() {
        if (null != $scope.testCase) for (var i = 0; i < $scope.testCase.children.length; i++) if ("SUT_MANUAL" !== $scope.testCase.children[i].testingType && "TA_MANUAL" !== $scope.testCase.children[i].testingType && "MANUAL" !== $scope.testCase.children[i].testingType) return !0;
        return !1;
    }, $scope.downloadReportAs = function(format, testStep) {
        var reportId = $scope.getTestStepValidationReport(testStep);
        if (null != reportId && void 0 != reportId) return ReportService.downloadTestStepValidationReport(reportId, format);
    }, $scope.savetestcasereport = function() {
        if (null != $scope.testCase) {
            $scope.saveButtonDisabled = !0, $scope.saveButtonText = "Saving...";
            var result = TestExecutionService.getTestCaseValidationResult($scope.testCase);
            result = void 0 != result ? result : null;
            var comments = TestExecutionService.getTestCaseComments($scope.testCase);
            comments = void 0 != comments ? comments : null;
            for (var testStepReportIds = [], i = 0; i < $scope.testCase.children.length; i++) testStepReportIds.push(TestExecutionService.getTestStepValidationReport($scope.testCase.children[i]));
            ReportService.saveTestCaseValidationReport($scope.testCase.id, testStepReportIds, result, comments, $scope.testCase.nav.testPlan, $scope.testCase.nav.testGroup).then(function(response) {
                Notification.success({
                    message: "Report saved successfully!",
                    templateUrl: "NotificationSuccessTemplate.html",
                    scope: $rootScope,
                    delay: 5e3
                }), $scope.saveButtonText = "Report Saved!";
            }, function(error) {
                Notification.error({
                    message: "Report could not be saved! <br>If error persists, please contact the website administrator.",
                    templateUrl: "NotificationErrorTemplate.html",
                    scope: $rootScope,
                    delay: 1e4
                }), $scope.saveButtonDisabled = !1, $scope.saveButtonText = "Save Test Case Report";
            });
        }
    }, $scope.toggleTransport = function(disabled) {
        $scope.transport.disabled = disabled, StorageService.set(StorageService.TRANSPORT_DISABLED, disabled), 
        null != CB.editor.instance && CB.editor.instance.setOption("readOnly", !disabled);
    }, $scope.editTestStepComment = function(testStep) {
        $scope.testExecutionService.testStepComments[testStep.id] || ($scope.testExecutionService.testStepComments[testStep.id] = ""), 
        $scope.testExecutionService.testStepCommentsChanged[testStep.id] = !0, $scope.testExecutionService.testStepCommentsChanges[testStep.id] = $scope.testExecutionService.testStepComments[testStep.id];
    }, $scope.deleteTestStepComment = function(testStep) {
        $scope.testExecutionService.testStepComments[testStep.id] = null, $scope.testExecutionService.testStepCommentsChanges[testStep.id] = null, 
        $scope.testExecutionService.testStepCommentsChanged[testStep.id] = !1, $scope.saveTestStepComment(testStep);
    }, $scope.resetTestStepComment = function(testStep) {
        $scope.testExecutionService.testStepCommentsChanged[testStep.id] = !1, $scope.testExecutionService.testStepCommentsChanges[testStep.id] = null;
    }, $scope.saveTestStepComment = function(testStep) {
        $scope.testExecutionService.testStepCommentsChanged[testStep.id] = !1, $scope.testExecutionService.testStepComments[testStep.id] = $scope.testExecutionService.testStepCommentsChanges[testStep.id], 
        $scope.updateTestStepValidationReport(testStep), $scope.testExecutionService.testStepCommentsChanges[testStep.id] = null;
    }, $scope.editTestCaseComment = function(testCase) {
        $scope.testExecutionService.testCaseComments[testCase.id] || ($scope.testExecutionService.testCaseComments[testCase.id] = ""), 
        $scope.testExecutionService.testCaseCommentsChanged[testCase.id] = !0, $scope.testExecutionService.testCaseCommentsChanges[testCase.id] = $scope.testExecutionService.testCaseComments[testCase.id];
    }, $scope.deleteTestCaseComment = function(testCase) {
        $scope.testExecutionService.testCaseComments[testCase.id] = null, $scope.testExecutionService.testCaseCommentsChanges[testCase.id] = null, 
        $scope.testExecutionService.testCaseCommentsChanged[testCase.id] = !1, $scope.saveTestCaseComment(testCase);
    }, $scope.resetTestCaseComment = function(testCase) {
        $scope.testExecutionService.testCaseCommentsChanged[testCase.id] = !1, $scope.testExecutionService.testCaseCommentsChanges[testCase.id] = null;
    }, $scope.saveTestCaseComment = function(testCase) {
        $scope.testExecutionService.testCaseCommentsChanged[testCase.id] = !1, $scope.testExecutionService.testCaseComments[testCase.id] = $scope.testExecutionService.testCaseCommentsChanges[testCase.id], 
        $scope.testExecutionService.testCaseCommentsChanges[testCase.id] = null;
    };
} ]), angular.module("cb").controller("CBTestCaseCtrl", [ "$scope", "$window", "$filter", "$rootScope", "CB", "$timeout", "CBTestPlanListLoader", "$sce", "StorageService", "TestCaseService", "TestStepService", "TestExecutionService", "CBTestPlanLoader", "User", "userInfoService", "ReportService", function($scope, $window, $filter, $rootScope, CB, $timeout, CBTestPlanListLoader, $sce, StorageService, TestCaseService, TestStepService, TestExecutionService, CBTestPlanLoader, User, userInfoService, ReportService) {
    $scope.cb = CB, $scope.error = null, $scope.selectedTestCase = CB.selectedTestCase, 
    $scope.testCase = CB.testCase, $scope.selectedTP = {
        id: null
    }, $scope.preSelectedTP = {
        id: null
    }, $scope.selectedScope = {
        key: null
    }, $scope.testPlanScopes = [], $scope.allTestPlanScopes = [ {
        key: "USER",
        name: "Private"
    }, {
        key: "GLOBAL",
        name: "Public"
    } ], $scope.testCases = [], $scope.testPlans = [], $scope.tree = {}, $scope.loading = !0, 
    $scope.loadingTP = !1, $scope.loadingTC = !1, $scope.loadingTPs = !1, $scope.collapsed = !1;
    var testCaseService = new TestCaseService();
    $scope.initTestCase = function() {
        if ($scope.error = null, $scope.loading = !0, $scope.testCases = null, userInfoService.isAuthenticated()) {
            $scope.testPlanScopes = $scope.allTestPlanScopes;
            var tmp = StorageService.get(StorageService.CB_SELECTED_TESTPLAN_SCOPE_KEY);
            $scope.selectedScope.key = tmp && null != tmp ? tmp : $scope.allTestPlanScopes[1].key;
        } else $scope.testPlanScopes = [ $scope.allTestPlanScopes[1] ], $scope.selectedScope.key = $scope.allTestPlanScopes[1].key;
        $scope.selectScope();
    }, $scope.$on("event:cb:initTestCase", function(event, args) {
        $scope.preSelectedTP.id = null, void 0 !== args && void 0 !== args.scope && void 0 !== args.group && ($scope.preSelectedTP.id = StorageService.get(StorageService.CB_SELECTED_TESTPLAN_ID_KEY)), 
        $scope.initTestCase();
    }), $rootScope.$on("event:logoutConfirmed", function() {
        $scope.initTestCase();
    }), $rootScope.$on("event:loginConfirmed", function() {
        $scope.initTestCase();
    });
    var findTPByPersistenceId = function(persistentId, testPlans) {
        for (var i = 0; i < testPlans.length; i++) if (testPlans[i].persistentId === persistentId) return testPlans[i];
        return null;
    };
    $scope.selectTP = function() {
        if ($scope.loadingTP = !0, $scope.errorTP = null, $scope.selectedTestCase = null, 
        $scope.selectedTP.id && null !== $scope.selectedTP.id && "" !== $scope.selectedTP.id) {
            var tcLoader = new CBTestPlanLoader($scope.selectedTP.id, $rootScope.domain);
            tcLoader.then(function(testPlan) {
                $scope.testCases = [ testPlan ], testCaseService.buildTree(testPlan), $scope.refreshTree(), 
                StorageService.set(StorageService.CB_SELECTED_TESTPLAN_ID_KEY, $scope.selectedTP.id), 
                $scope.selectTestCase(testPlan), $scope.loadingTP = !1;
            }, function(error) {
                $scope.loadingTP = !1, $scope.errorTP = "Sorry, Cannot load the test cases. Please try again";
            });
        } else $scope.testCases = null, StorageService.set(StorageService.CB_SELECTED_TESTPLAN_ID_KEY, ""), 
        $scope.loadingTP = !1;
    }, $scope.selectScope = function() {
        if ($scope.errorTP = null, $scope.selectedTestCase = null, $scope.testPlans = null, 
        $scope.testCases = null, $scope.errorTP = null, $scope.loadingTP = !1, StorageService.set(StorageService.CB_SELECTED_TESTPLAN_SCOPE_KEY, $scope.selectedScope.key), 
        $scope.selectedScope.key && null !== $scope.selectedScope.key && "" !== $scope.selectedScope.key) {
            if (null != $rootScope.domain && null != $rootScope.domain.domain) {
                $scope.loadingTP = !0;
                var tcLoader = new CBTestPlanListLoader($scope.selectedScope.key, $rootScope.domain.domain);
                tcLoader.then(function(testPlans) {
                    $scope.error = null, $scope.testPlans = $filter("orderBy")(testPlans, "position");
                    var targetId = null;
                    if ($scope.testPlans.length > 0) {
                        if (1 === $scope.testPlans.length) targetId = $scope.testPlans[0].id; else if (null !== $scope.preSelectedTP.id) targetId = $scope.preSelectedTP.id; else if (null !== StorageService.get(StorageService.CB_SELECTED_TESTPLAN_ID_KEY)) {
                            var previousTpId = StorageService.get(StorageService.CB_SELECTED_TESTPLAN_ID_KEY);
                            targetId = void 0 == previousTpId || null == previousTpId ? $scope.testPlans[0].id : previousTpId;
                        } else if (userInfoService.isAuthenticated()) {
                            var lastTestPlanPersistenceId = userInfoService.getLastTestPlanPersistenceId(), tp = findTPByPersistenceId(lastTestPlanPersistenceId, $scope.testPlans);
                            targetId = null != tp ? tp.id : $scope.testPlans[0].id;
                        } else targetId = $scope.testPlans[0].id;
                        $scope.selectedTP.id = targetId.toString(), $scope.selectTP();
                    } else $scope.loadingTP = !1;
                    $scope.loading = !1;
                }, function(error) {
                    $scope.loadingTP = !1, $scope.loading = !1, $scope.error = "Sorry, Cannot load the test plans. Please try again";
                });
            }
        } else StorageService.set(StorageService.CB_SELECTED_TESTPLAN_ID_KEY, "");
    }, $scope.refreshTree = function() {
        $timeout(function() {
            if (null != $scope.testCases) if ("function" == typeof $scope.tree.build_all) {
                $scope.tree.build_all($scope.testCases);
                var b = $scope.tree.get_first_branch();
                null != b && b && $scope.tree.expand_branch(b);
                var testCase = null, id = StorageService.get(StorageService.CB_SELECTED_TESTCASE_ID_KEY), type = StorageService.get(StorageService.CB_SELECTED_TESTCASE_TYPE_KEY);
                if (null != id && null != type) {
                    for (var i = 0; i < $scope.testCases.length; i++) {
                        var found = testCaseService.findOneByIdAndType(id, type, $scope.testCases[i]);
                        if (null != found) {
                            testCase = found;
                            break;
                        }
                    }
                    null != testCase && $scope.selectNode(id, type);
                }
                if (testCase = null, id = StorageService.get(StorageService.CB_LOADED_TESTCASE_ID_KEY), 
                type = StorageService.get(StorageService.CB_LOADED_TESTCASE_TYPE_KEY), null != id && null != type) {
                    for (var i = 0; i < $scope.testCases.length; i++) {
                        var found = testCaseService.findOneByIdAndType(id, type, $scope.testCases[i]);
                        if (null != found) {
                            testCase = found;
                            break;
                        }
                    }
                    if (null != testCase) {
                        var tab = StorageService.get(StorageService.ACTIVE_SUB_TAB_KEY);
                        $scope.loadTestCase(testCase, tab, !1);
                    }
                }
            } else $scope.error = "Something went wrong. Please refresh your page again.";
            $scope.loading = !1;
        }, 1e3);
    }, $scope.refreshLoadedTestCase = function() {
        var testCase = null, id = StorageService.get(StorageService.CB_LOADED_TESTCASE_ID_KEY), type = StorageService.get(StorageService.CB_LOADED_TESTCASE_TYPE_KEY);
        if (null != id && null != type) {
            for (var i = 0; i < $scope.testCases.length; i++) {
                var found = testCaseService.findOneByIdAndType(id, type, $scope.testCases[i]);
                if (null != found) {
                    testCase = found;
                    break;
                }
            }
            if (null != testCase) {
                var tab = StorageService.get(StorageService.ACTIVE_SUB_TAB_KEY);
                $scope.loadTestCase(testCase, tab, !1);
            }
        }
    }, $scope.isSelectable = function(node) {
        return !0;
    }, $scope.selectTestCase = function(node) {
        $scope.loadingTC = !0, $scope.selectedTestCase = node, $scope.cb.selectedTestCase = node, 
        StorageService.set(StorageService.CB_SELECTED_TESTCASE_ID_KEY, node.id), StorageService.set(StorageService.CB_SELECTED_TESTCASE_TYPE_KEY, node.type), 
        $timeout(function() {
            $scope.$broadcast("cb:testCaseSelected", $scope.selectedTestCase), $scope.loadingTC = !1;
        });
    }, $scope.selectNode = function(id, type) {
        $timeout(function() {
            testCaseService.selectNodeByIdAndType($scope.tree, id, type);
        }, 0);
    }, $scope.loadTestCase = function(testCase, tab, clear) {
        if (void 0 === clear || clear === !0) {
            StorageService.remove(StorageService.CB_EDITOR_CONTENT_KEY);
            var id = StorageService.get(StorageService.CB_LOADED_TESTCASE_ID_KEY), type = StorageService.get(StorageService.CB_LOADED_TESTCASE_TYPE_KEY);
            null != id && void 0 != id && ("TestCase" === type ? TestExecutionService.clearTestCase(id) : "TestStep" === type && TestExecutionService.clearTestStep(id), 
            StorageService.remove(StorageService.CB_LOADED_TESTCASE_ID_KEY), StorageService.remove(StorageService.CB_LOADED_TESTCASE_TYPE_KEY)), 
            id = StorageService.get(StorageService.CB_LOADED_TESTSTEP_ID_KEY), type = StorageService.get(StorageService.CB_LOADED_TESTSTEP_TYPE_KEY), 
            null != id && void 0 != id && (TestExecutionService.clearTestStep(id), StorageService.remove(StorageService.CB_LOADED_TESTCASE_ID_KEY), 
            StorageService.remove(StorageService.CB_LOADED_TESTCASE_TYPE_KEY));
        }
        StorageService.set(StorageService.CB_LOADED_TESTCASE_ID_KEY, testCase.id), StorageService.set(StorageService.CB_LOADED_TESTCASE_TYPE_KEY, testCase.type), 
        "TestStep" === testCase.type && $rootScope.$emit("cb:updateSavedReports", testCase), 
        $timeout(function() {
            $rootScope.$broadcast("cb:testCaseLoaded", testCase, tab);
        }), null != CB.editor && null != CB.editor.instance && CB.editor.instance.setOption("readOnly", !1);
    }, $scope.expandAll = function() {
        null != $scope.tree && $scope.tree.expand_all();
    }, $scope.collapseAll = function() {
        null != $scope.tree && $scope.tree.collapse_all();
    }, $rootScope.$on("event:logoutConfirmed", function() {
        $scope.initTestCase();
    }), $rootScope.$on("event:loginConfirmed", function() {
        $scope.initTestCase();
    }), $rootScope.$on("event:refreshLoadedTestCase", function() {
        $scope.refreshLoadedTestCase();
    }), $rootScope.$on("cb:updateSavedReports", function(event, testStep) {
        userInfoService.isAuthenticated() && $rootScope.isReportSavingSupported() && $timeout(function() {
            ReportService.getAllIndependantTSByAccountIdAndDomainAndtestStepId($rootScope.domain.domain, testStep.persistentId).then(function(reports) {
                null !== reports ? ($scope.cb.selectedSavedReport = null, $scope.cb.savedReports = reports) : ($scope.cb.savedReports = [], 
                $scope.cb.selectedSavedReport = null);
            }, function(error) {
                $scope.cb.selectedSavedReport = null, $scope.cb.savedReports = [], $scope.loadingAll = !1, 
                $scope.error = "Sorry, Cannot load the reports. Please try again. \n DEBUG:" + error;
            });
        }, 100);
    });
} ]), angular.module("cb").controller("CBSavedReportCtrl", [ "$scope", "$sce", "$http", "CB", "ReportService", "$modal", function($scope, $sce, $http, CB, ReportService, $modal) {
    $scope.cb = CB, $scope.selectReport = function(report) {
        $scope.loading = !0, ReportService.getUserTCReportHTML(report.id).then(function(report) {
            null !== report && ($scope.cb.selectedSavedReport = report);
        }, function(error) {
            $scope.error = "Sorry, Cannot load the report data. Please try again. \n DEBUG:" + error;
        }).finally(function() {
            $scope.loading = !1;
        });
    }, $scope.downloadAs = function(format) {
        if ($scope.cb.selectedSavedReport) return ReportService.downloadUserTestStepValidationReport($scope.cb.selectedSavedReport.id, format);
    }, $scope.deleteReport = function(report) {
        var modalInstance = $modal.open({
            templateUrl: "confirmReportDelete.html",
            controller: "ConfirmDialogCtrl",
            size: "md",
            backdrop: !0,
            keyboard: !0
        });
        modalInstance.result.then(function(resultDiag) {
            resultDiag && ReportService.deleteTSReport(report.id).then(function(result) {
                var index = $scope.reports.indexOf(report);
                index > -1 && $scope.reports.splice(index, 1), Notification.success({
                    message: "Report deleted successfully!",
                    templateUrl: "NotificationSuccessTemplate.html",
                    scope: $rootScope,
                    delay: 5e3
                });
            }, function(error) {
                Notification.error({
                    message: "Report deletion failed! <br>If error persists, please contact the website administrator.",
                    templateUrl: "NotificationErrorTemplate.html",
                    scope: $rootScope,
                    delay: 1e4
                });
            });
        }, function(resultDiag) {});
    };
} ]), angular.module("cb").controller("CBValidatorCtrl", [ "$scope", "$http", "CB", "$window", "$timeout", "$modal", "NewValidationResult", "$rootScope", "ServiceDelegator", "StorageService", "TestExecutionService", "MessageUtil", "FileUpload", function($scope, $http, CB, $window, $timeout, $modal, NewValidationResult, $rootScope, ServiceDelegator, StorageService, TestExecutionService, MessageUtil, FileUpload) {
    $scope.cb = CB, $scope.testStep = null, $scope.message = CB.message, $scope.loading = !0, 
    $scope.error = null, $scope.vError = null, $scope.vLoading = !0, $scope.mError = null, 
    $scope.mLoading = !0, $scope.counter = 0, $scope.type = "cb", $scope.loadRate = 4e3, 
    $scope.tokenPromise = null, $scope.editorInit = !1, $scope.nodelay = !1, $scope.resized = !1, 
    $scope.selectedItem = null, $scope.activeTab = 0, $scope.tError = null, $scope.tLoading = !1, 
    $scope.dqaCodes = null != StorageService.get(StorageService.DQA_OPTIONS_KEY) ? angular.fromJson(StorageService.get(StorageService.DQA_OPTIONS_KEY)) : [], 
    $scope.domain = null, $scope.protocol = null, $scope.hasNonPrintable = !1, $scope.showDQAOptions = function() {
        var modalInstance = $modal.open({
            templateUrl: "DQAConfig.html",
            controller: "DQAConfigCtrl",
            windowClass: "dq-modal",
            animation: !0,
            keyboard: !1,
            backdrop: !1
        });
        modalInstance.result.then(function(selectedCodes) {
            $scope.dqaCodes = selectedCodes;
        }, function() {});
    }, $scope.isTestCase = function() {
        return null != CB.testCase && "TestCase" === CB.testCase.type;
    }, $scope.refreshEditor = function() {
        $timeout(function() {
            $scope.editor && $scope.editor.refresh();
        }, 1e3);
    }, $scope.loadExampleMessage = function() {
        if (null != $scope.testStep) {
            var testContext = $scope.testStep.testContext;
            if (testContext) {
                var message = testContext.message && null != testContext.message ? testContext.message.content : "";
                $scope.isTestCase() && TestExecutionService.setTestStepExecutionMessage($scope.testStep, message), 
                $scope.nodelay = !0, $scope.cb.editor.instance.doc.setValue(message), $scope.execute();
            }
        }
    }, $scope.uploadMessage = function(file, errFiles) {
        $scope.f = file, FileUpload.uploadMessage(file, errFiles).then(function(response) {
            $timeout(function() {
                file.result = response.data;
                var result = response.data, fileName = file.name;
                $scope.nodelay = !0;
                var tmp = angular.fromJson(result);
                $scope.cb.message.name = fileName, $scope.cb.editor.instance.doc.setValue(tmp.content), 
                $scope.mError = null, $scope.execute(), Notification.success({
                    message: "File " + fileName + " successfully uploaded!",
                    templateUrl: "NotificationSuccessTemplate.html",
                    scope: $rootScope,
                    delay: 3e4
                });
            });
        }, function(response) {
            $scope.mError = response.data;
        });
    }, $scope.setLoadRate = function(value) {
        $scope.loadRate = value;
    }, $scope.initCodemirror = function() {
        $scope.editor = CodeMirror.fromTextArea(document.getElementById("cb-textarea"), {
            lineNumbers: !0,
            fixedGutter: !0,
            theme: "elegant",
            readOnly: !1,
            showCursorWhenSelecting: !0
        }), $scope.editor.setSize("100%", 345), $scope.editor.on("keyup", function() {
            $timeout(function() {
                var msg = $scope.editor.doc.getValue();
                $scope.error = null, $scope.tokenPromise && ($timeout.cancel($scope.tokenPromise), 
                $scope.tokenPromise = void 0), "" !== msg.trim() ? $scope.tokenPromise = $timeout(function() {
                    $scope.execute();
                }, $scope.loadRate) : $scope.execute();
            });
        }), $scope.editor.on("dblclick", function(editor) {
            $timeout(function() {
                var coordinate = ServiceDelegator.getCursorService($scope.testStep.testContext.format).getCoordinate($scope.editor, $scope.cb.tree);
                coordinate && null != coordinate && (coordinate.start.index = coordinate.start.index + 1, 
                coordinate.end.index = coordinate.end.index + 1, $scope.cb.cursor.init(coordinate, !0), 
                ServiceDelegator.getTreeService($scope.testStep.testContext.format).selectNodeByIndex($scope.cb.tree.root, CB.cursor, CB.message.content));
            });
        });
    }, $scope.validateMessage = function() {
        try {
            if (null != $scope.testStep) if ("" !== $scope.cb.message.content && null != $scope.testStep.testContext) {
                $scope.vLoading = !0, $scope.vError = null, TestExecutionService.deleteTestStepValidationReport($scope.testStep);
                var validator = ServiceDelegator.getMessageValidator($scope.testStep.testContext.format).validate($scope.testStep.testContext.id, $scope.cb.message.content, $scope.testStep.nav, "Based", [], "1223");
                validator.then(function(mvResult) {
                    $scope.vLoading = !1, $scope.setTestStepValidationReport(mvResult);
                }, function(error) {
                    $scope.vLoading = !1, $scope.vError = error, $scope.setTestStepValidationReport(null);
                });
            } else {
                var reportId = TestExecutionService.getTestStepValidationReport($scope.testStep);
                $scope.setTestStepValidationReport({
                    reportId: reportId
                }), $scope.vLoading = !1, $scope.vError = null;
            }
        } catch (error) {
            $scope.vLoading = !1, $scope.vError = null, $scope.setTestStepValidationReport(null);
        }
    }, $scope.setTestStepValidationReport = function(mvResult) {
        null != $scope.testStep && (null != mvResult && void 0 != mvResult && null != mvResult.reportId && ($scope.completeStep($scope.testStep), 
        TestExecutionService.setTestStepValidationReport($scope.testStep, mvResult.reportId)), 
        $rootScope.$emit("cb:validationResultLoaded", mvResult, $scope.testStep, $scope.getTestType()));
    }, $scope.setTestStepMessageTree = function(messageObject) {
        $scope.buildMessageTree(messageObject);
        var tree = messageObject && null != messageObject && messageObject.elements ? messageObject : void 0;
        TestExecutionService.setTestStepMessageTree($scope.testStep, tree);
    }, $scope.buildMessageTree = function(messageObject) {
        if (null != $scope.testStep) {
            var elements = messageObject && null != messageObject && messageObject.elements ? messageObject.elements : [];
            "function" == typeof $scope.cb.tree.root.build_all && $scope.cb.tree.root.build_all(elements);
            var delimeters = messageObject && null != messageObject && messageObject.delimeters ? messageObject.delimeters : [];
            ServiceDelegator.updateEditorMode($scope.editor, delimeters, $scope.testStep.testContext.format), 
            ServiceDelegator.getEditorService($scope.testStep.testContext.format).setEditor($scope.editor), 
            ServiceDelegator.getTreeService($scope.testStep.testContext.format).setEditor($scope.editor);
        }
    }, $scope.clearMessage = function() {
        $scope.nodelay = !0, $scope.mError = null, null != $scope.testStep && (TestExecutionService.deleteTestStepValidationReport($scope.testStep), 
        TestExecutionService.deleteTestStepMessageTree($scope.testStep)), $scope.editor && ($scope.editor.doc.setValue(""), 
        $scope.execute());
    }, $scope.saveMessage = function() {
        $scope.cb.message.download();
    }, $scope.parseMessage = function() {
        try {
            if (null != $scope.testStep) if ("" != $scope.cb.message.content && null != $scope.testStep.testContext) {
                $scope.tLoading = !0, TestExecutionService.deleteTestStepMessageTree($scope.testStep);
                var parsed = ServiceDelegator.getMessageParser($scope.testStep.testContext.format).parse($scope.testStep.testContext.id, $scope.cb.message.content);
                parsed.then(function(value) {
                    $scope.tLoading = !1, $scope.setTestStepMessageTree(value);
                }, function(error) {
                    $scope.tLoading = !1, $scope.tError = error, $scope.setTestStepMessageTree([]);
                });
            } else $scope.setTestStepMessageTree([]), $scope.tError = null, $scope.tLoading = !1;
        } catch (error) {
            $scope.tLoading = !1, $scope.tError = error;
        }
    }, $scope.onNodeSelect = function(node) {
        ServiceDelegator.getTreeService($scope.testStep.testContext.format).getEndIndex(node, $scope.cb.message.content), 
        $scope.cb.cursor.init(node.data, !1), ServiceDelegator.getEditorService($scope.testStep.testContext.format).select($scope.editor, $scope.cb.cursor);
    }, $scope.execute = function() {
        if ($scope.tokenPromise && ($timeout.cancel($scope.tokenPromise), $scope.tokenPromise = void 0), 
        $scope.error = null, $scope.tError = null, $scope.mError = null, $scope.vError = null, 
        $scope.cb.message.content = $scope.editor.doc.getValue(), $scope.setHasNonPrintableCharacters(), 
        StorageService.set(StorageService.CB_EDITOR_CONTENT_KEY, $scope.cb.message.content), 
        $scope.refreshEditor(), $scope.isTestCase() && $scope.isTestCaseCompleted()) {
            var reportId = TestExecutionService.getTestStepValidationReport($scope.testStep);
            $scope.setTestStepValidationReport({
                reportId: reportId
            }), $scope.setTestStepMessageTree(TestExecutionService.getTestStepMessageTree($scope.testStep));
        } else TestExecutionService.setTestStepExecutionMessage($scope.testStep, $scope.cb.message.content), 
        $scope.validateMessage(), $scope.parseMessage();
    }, $scope.executeWithMessage = function(content) {
        $scope.editor && ($scope.editor.doc.setValue(content), $scope.execute());
    }, $scope.clear = function() {
        $scope.vLoading = !1, $scope.tLoading = !1, $scope.mLoading = !1, $scope.error = null, 
        $scope.tError = null, $scope.mError = null, $scope.vError = null, $scope.setTestStepValidationReport(null);
    }, $scope.removeDuplicates = function() {
        $scope.vLoading = !0, $scope.$broadcast("cb:removeDuplicates");
    }, $scope.clear(), $scope.initCodemirror(), $scope.$on("cb:refreshEditor", function(event) {
        $scope.refreshEditor();
    }), $scope.$on("cb:clearEditor", function(event) {
        $scope.clearMessage();
    }), $rootScope.$on("cb:reportLoaded", function(event, report) {
        null != $scope.testStep && TestExecutionService.setTestStepValidationReport($scope.testStep, report);
    }), $scope.$on("cb:testStepLoaded", function(event, testStep) {
        if ($scope.clear(), $scope.testStep = testStep, null != $scope.testStep.testContext) {
            $scope.cb.editor = ServiceDelegator.getEditor($scope.testStep.testContext.format), 
            $scope.cb.editor.instance = $scope.editor, $scope.cb.cursor = ServiceDelegator.getCursor($scope.testStep.testContext.format);
            var content = null;
            $scope.isTestCase() ? ($scope.nodelay = !0, content = TestExecutionService.getTestStepExecutionMessage($scope.testStep), 
            void 0 == content && (content = "")) : ($scope.nodelay = !1, content = null == StorageService.get(StorageService.CB_EDITOR_CONTENT_KEY) ? "" : StorageService.get(StorageService.CB_EDITOR_CONTENT_KEY)), 
            $scope.executeWithMessage(content);
        }
    }), $scope.$on("cb:removeTestStep", function(event, testStep) {
        $scope.testStep = null;
    }), $scope.$on("cb:loadEditorContent", function(event, message) {
        $scope.nodelay = !0;
        var content = null == message ? "" : message;
        $scope.editor.doc.setValue(content), $scope.cb.message.id = null, $scope.cb.message.name = "", 
        $scope.execute();
    }), $rootScope.$on("cb:duplicatesRemoved", function(event, report) {
        $scope.vLoading = !1;
    }), $scope.initValidation = function() {}, $scope.expandAll = function() {
        null != $scope.cb.tree.root && $scope.cb.tree.root.expand_all();
    }, $scope.collapseAll = function() {
        null != $scope.cb.tree.root && $scope.cb.tree.root.collapse_all();
    }, $scope.setHasNonPrintableCharacters = function() {
        $scope.hasNonPrintable = MessageUtil.hasNonPrintable($scope.cb.message.content);
    }, $scope.showMessageWithHexadecimal = function() {
        $modal.open({
            templateUrl: "MessageWithHexadecimal.html",
            controller: "MessageWithHexadecimalDlgCtrl",
            windowClass: "valueset-modal",
            animation: !1,
            keyboard: !0,
            backdrop: !0,
            resolve: {
                original: function() {
                    return $scope.cb.message.content;
                }
            }
        });
    };
} ]), angular.module("cb").controller("CBProfileViewerCtrl", [ "$scope", "CB", function($scope, CB) {
    $scope.cb = CB;
} ]), angular.module("cb").controller("CBReportCtrl", [ "$scope", "$sce", "$http", "CB", function($scope, $sce, $http, CB) {
    $scope.cb = CB;
} ]), angular.module("cb").controller("CBVocabularyCtrl", [ "$scope", "CB", function($scope, CB) {
    $scope.cb = CB;
} ]), angular.module("cb").controller("PastTestStepConsoleCtrl", function($scope, $modalInstance, title, log) {
    $scope.title = title, $scope.log = log, $scope.cancel = function() {
        $modalInstance.dismiss("cancel");
    }, $scope.close = function() {
        $modalInstance.close();
    };
}), angular.module("cb").controller("CurrentTestStepConsoleCtrl", function($scope, $modalInstance, title, logger) {
    $scope.title = title, $scope.logger = logger, $scope.cancel = function() {
        $modalInstance.dismiss("cancel");
    }, $scope.close = function() {
        $modalInstance.close();
    };
}), angular.module("cb").controller("CBManualValidationCtrl", [ "$scope", "CB", "$http", "TestExecutionService", "$timeout", "ManualReportService", "$rootScope", function($scope, CB, $http, TestExecutionService, $timeout, ManualReportService, $rootScope) {
    $scope.cb = CB, $scope.saving = !1, $scope.error = null, $scope.testStep = null, 
    $scope.report = null, $scope.testExecutionService = TestExecutionService, $scope.saved = !1, 
    $scope.error = null, $scope.$on("cb:manualTestStepLoaded", function(event, testStep) {
        $scope.saved = !1, $scope.saving = !1, $scope.error = null, $scope.testStep = testStep, 
        $scope.report = void 0 === TestExecutionService.getTestStepValidationReport(testStep) || null === TestExecutionService.getTestStepValidationReport(testStep) ? {
            result: {
                value: "",
                comments: ""
            },
            html: null
        } : TestExecutionService.getTestStepValidationReport(testStep);
    });
} ]), angular.module("cb").controller("CBManualReportCtrl", [ "$scope", "$sce", "$http", "CB", function($scope, $sce, $http, CB) {
    $scope.cb = CB;
} ]), angular.module("cb").controller("CBTestManagementCtrl", function($scope, $window, $filter, $rootScope, CB, $timeout, $sce, StorageService, TestCaseService, TestStepService, CBTestPlanManager, User, userInfoService, $modal, Notification, $modalStack, $location, $routeParams) {
    $scope.selectedTestCase = CB.selectedTestCase, $scope.testCase = CB.testCase, $scope.selectedTP = {
        id: null
    }, $scope.selectedScope = {
        key: null
    }, $scope.testPlanScopes = null, $scope.testCases = [], $scope.testPlans = [], $scope.tree = {}, 
    $scope.loading = !0, $scope.loadingTP = !1, $scope.loadingTC = !1, $scope.loadingTPs = !1, 
    $scope.allTestPlanScopes = [ {
        key: "USER",
        name: "Private"
    }, {
        key: "GLOBAL",
        name: "Public"
    } ], $scope.token = $routeParams.x, $scope.domain = $routeParams.d, $scope.error = null, 
    $scope.collapsed = !1;
    var testCaseService = new TestCaseService();
    $scope.$on("event:cb:initManagement", function() {
        $scope.initTestCase();
    }), $scope.initTestCase = function() {
        if ($rootScope.isCbManagementSupported() && userInfoService.isAuthenticated() && $rootScope.hasWriteAccess()) {
            if ($scope.error = null, $scope.loading = !0, $scope.testPlans = null, userInfoService.isAdmin() || userInfoService.isSupervisor()) {
                $scope.testPlanScopes = $scope.allTestPlanScopes;
                var tmp = StorageService.get(StorageService.CB_MANAGE_SELECTED_TESTPLAN_SCOPE_KEY);
                $scope.selectedScope.key = tmp && null != tmp ? tmp : $scope.testPlanScopes[1].key;
            } else $scope.testPlanScopes = [ $scope.allTestPlanScopes[0] ], $scope.selectedScope.key = $scope.testPlanScopes[0].key;
            $scope.selectScope();
        }
    };
    $scope.get_icon_type = function(node) {
        if ("TestObject" === node.type || "TestStep" === node.type) {
            var connType = node.testingType;
            return "TA_MANUAL" === connType || "SUT_MANUAL" === connType ? "fa fa-wrench" : "SUT_RESPONDER" === connType || "SUT_INITIATOR" === connType ? "fa fa-arrow-right" : "TA_RESPONDER" === connType || "TA_INITIATOR" === connType ? "fa fa-arrow-left" : "fa fa-check-square-o";
        }
        return "";
    }, $scope.selectTP = function() {
        $scope.loadingTP = !0, $scope.errorTP = null, $scope.selectedTestCase = null, $scope.selectedTP.id && null !== $scope.selectedTP.id && "" !== $scope.selectedTP.id ? CBTestPlanManager.getTestPlan($scope.selectedTP.id).then(function(testPlan) {
            $scope.testCases = [ testPlan ], testCaseService.buildTree(testPlan), StorageService.set(StorageService.CB_MANAGE_SELECTED_TESTPLAN_ID_KEY, $scope.selectedTP.id), 
            $scope.selectTestNode(testPlan), $scope.loadingTP = !1;
        }, function(error) {
            $scope.loadingTP = !1, $scope.errorTP = "Sorry, Cannot load the test cases. Please try again";
        }) : ($scope.testCases = null, StorageService.set(StorageService.CB_MANAGE_SELECTED_TESTPLAN_ID_KEY, ""), 
        $scope.loadingTP = !1);
    }, $scope.selectScope = function() {
        $scope.errorTP = null, $scope.selectedTestCase = null, $scope.testPlans = null, 
        $scope.testCases = null, $scope.errorTP = null, $scope.loadingTP = !1, StorageService.set(StorageService.CB_MANAGE_SELECTED_TESTPLAN_SCOPE_KEY, $scope.selectedScope.key), 
        $scope.selectedScope.key && null !== $scope.selectedScope.key && "" !== $scope.selectedScope.key && null != $rootScope.domain ? $rootScope.domain && null != $rootScope.domain.domain && ($scope.loadingTP = !0, 
        CBTestPlanManager.getTestPlans($scope.selectedScope.key, $rootScope.domain.domain).then(function(testPlans) {
            $scope.error = null, $scope.testPlans = $filter("orderBy")(testPlans, "position");
            var targetId = null;
            if ($scope.testPlans.length > 0) {
                if (1 === $scope.testPlans.length && (targetId = $scope.testPlans[0].id), null == targetId) {
                    var previousTpId = StorageService.get(StorageService.CB_MANAGE_SELECTED_TESTPLAN_ID_KEY);
                    targetId = void 0 == previousTpId || null == previousTpId ? "" : previousTpId;
                }
                $scope.selectedTP.id = targetId.toString(), $scope.selectTP();
            } else $scope.loadingTP = !1;
            $scope.loading = !1;
        }, function(error) {
            $scope.loadingTP = !1, $scope.loading = !1, $scope.error = "Sorry, Cannot load the test plans. Please try again";
        })) : StorageService.set(StorageService.CB_MANAGE_SELECTED_TESTPLAN_ID_KEY, "");
    }, $scope.refreshTree = function() {
        $timeout(function() {
            if (null != $scope.testCases) if ("function" == typeof $scope.tree.build_all) {
                $scope.tree.build_all($scope.testCases);
                var b = $scope.tree.get_first_branch();
                null != b && b && $scope.tree.expand_branch(b);
                var testCase = null, id = StorageService.get(StorageService.CB_MANAGE_SELECTED_TESTCASE_ID_KEY), type = StorageService.get(StorageService.CB_MANAGE_SELECTED_TESTCASE_TYPE_KEY);
                if (null != id && null != type) {
                    for (var i = 0; i < $scope.testCases.length; i++) {
                        var found = testCaseService.findOneByIdAndType(id, type, $scope.testCases[i]);
                        if (null != found) {
                            testCase = found;
                            break;
                        }
                    }
                    null != testCase && $scope.selectNode(id, type);
                }
                if (testCase = null, id = StorageService.get(StorageService.CB_MANAGE_LOADED_TESTCASE_ID_KEY), 
                type = StorageService.get(StorageService.CB_MANAGE_LOADED_TESTCASE_TYPE_KEY), null != id && null != type) {
                    for (var i = 0; i < $scope.testCases.length; i++) {
                        var found = testCaseService.findOneByIdAndType(id, type, $scope.testCases[i]);
                        if (null != found) {
                            testCase = found;
                            break;
                        }
                    }
                    if (null != testCase) {
                        var tab = StorageService.get(StorageService.ACTIVE_SUB_TAB_KEY);
                        $scope.loadTestCase(testCase, tab, !1);
                    }
                }
            } else $scope.error = "Something went wrong. Please refresh your page again.";
            $scope.loading = !1;
        }, 1e3);
    }, $scope.isSelectable = function(node) {
        return !0;
    }, $scope.selectTestNode = function(node) {
        $scope.loadingTC = !0, $scope.error = null, $scope.selectedTestCase = node, StorageService.set(StorageService.CB_MANAGE_SELECTED_TESTCASE_ID_KEY, node.id), 
        StorageService.set(StorageService.CB_MANAGE_SELECTED_TESTCASE_TYPE_KEY, node.type), 
        $timeout(function() {
            $scope.$broadcast("cb-manage:testCaseSelected", $scope.selectedTestCase), $scope.loadingTC = !1;
        });
    }, $scope.selectNode = function(id, type) {
        $timeout(function() {
            testCaseService.selectNodeByIdAndType($scope.tree, id, type);
        }, 0);
    }, $scope.deleteTreeNode = function(node, potentialParent) {
        if (potentialParent.children && potentialParent.children.length > 0) for (var i = 0; i < potentialParent.children.length; i++) {
            var child = potentialParent.children[i];
            if (child == node) return potentialParent.children.splice(i, 1), !0;
            var done = $scope.deleteTreeNode(node, child);
            if (done) return !0;
        }
        return !1;
    }, $scope.afterDelete = function(node) {
        for (var i = 0; i < $scope.testCases.length; i++) if (1 == $scope.deleteTreeNode(node, $scope.testCases[i])) {
            node === $scope.selectedTestCase && ($scope.selectedTestCase = null);
            break;
        }
    }, $scope.deleteTestStep = function(testStep) {
        $scope.error = null;
        var modalInstance = $modal.open({
            templateUrl: "views/cb/manage/confirm-delete-teststep.html",
            controller: "ConfirmDialogCtrl",
            size: "md",
            backdrop: "static",
            keyboard: !1
        });
        modalInstance.result.then(function(result) {
            result && CBTestPlanManager.deleteTestStep(testStep).then(function(result) {
                "SUCCESS" === result.status ? ($scope.afterDelete(testStep), Notification.success({
                    message: "Test Step deleted successfully !",
                    templateUrl: "NotificationSuccessTemplate.html",
                    scope: $rootScope,
                    delay: 5e3
                })) : $scope.error = result.message;
            }, function(error) {
                $scope.error = "Sorry, Cannot delete the test step. Please try again. \n DEBUG:" + error;
            });
        }, function(result) {});
    }, $scope.deleteTestCase = function(testCase) {
        $scope.error = null;
        var modalInstance = $modal.open({
            templateUrl: "views/cb/manage/confirm-delete-testcase.html",
            controller: "ConfirmDialogCtrl",
            size: "md",
            backdrop: "static",
            keyboard: !1
        });
        modalInstance.result.then(function(result) {
            result && CBTestPlanManager.deleteTestCase(testCase).then(function(result) {
                "SUCCESS" === result.status ? ($scope.afterDelete(testCase), Notification.success({
                    message: "Test Case deleted successfully !",
                    templateUrl: "NotificationSuccessTemplate.html",
                    scope: $rootScope,
                    delay: 5e3
                })) : $scope.error = result.message;
            }, function(error) {
                $scope.error = "Sorry, Cannot delete the test case. Please try again. \n DEBUG:" + error;
            });
        }, function(result) {});
    }, $scope.deleteTestCaseGroup = function(testCaseGroup) {
        $scope.error = null;
        var modalInstance = $modal.open({
            templateUrl: "views/cb/manage/confirm-delete-testgroup.html",
            controller: "ConfirmDialogCtrl",
            size: "md",
            backdrop: "static",
            keyboard: !1
        });
        modalInstance.result.then(function(result) {
            result && CBTestPlanManager.deleteTestCaseGroup(testCaseGroup).then(function(result) {
                "SUCCESS" === result.status ? ($scope.afterDelete(testCaseGroup), Notification.success({
                    message: "Test Case Group deleted successfully !",
                    templateUrl: "NotificationSuccessTemplate.html",
                    scope: $rootScope,
                    delay: 5e3
                })) : $scope.error = result.message;
            }, function(error) {
                $scope.error = "Sorry, Cannot delete the test case group. Please try again. \n DEBUG:" + error;
            });
        }, function(result) {});
    }, $scope.deleteTestPlan = function(testPlan) {
        $scope.error = null;
        var modalInstance = $modal.open({
            templateUrl: "views/cb/manage/confirm-delete-testplan.html",
            controller: "ConfirmDialogCtrl",
            size: "md",
            backdrop: "static",
            keyboard: !1
        });
        modalInstance.result.then(function(result) {
            result && CBTestPlanManager.deleteTestPlan(testPlan).then(function(result) {
                if ("SUCCESS" === result.status) {
                    if (null != $scope.testPlans) {
                        for (var ind = -1, i = 0; i < $scope.testPlans.length; i++) if ($scope.testPlans[i].id == $scope.testCases[0].id) {
                            ind = i;
                            break;
                        }
                        ind > -1 && $scope.testPlans.splice(ind, 1), $scope.testCases = [], $scope.selectedTestCase = null;
                    }
                    Notification.success({
                        message: "Test Plan deleted successfully !",
                        templateUrl: "NotificationSuccessTemplate.html",
                        scope: $rootScope,
                        delay: 5e3
                    });
                } else $scope.error = result.message;
            }, function(error) {
                $scope.error = "Sorry, Cannot delete the test plan. Please try again. \n DEBUG:" + error;
            });
        }, function(result) {});
    }, $scope.editNodeName = function(node) {
        node.editName = node.name, node.edit = !0, node.disableEdit = !1;
    }, $scope.resetNodeName = function(node) {
        node.editName = null, node.edit = !1;
    }, $scope.deleteTestNode = function(node) {
        node.editName != node.name && ("TestPlan" === node.type ? $scope.deleteTestPlan(node) : "TestCaseGroup" === node.type ? $scope.deleteTestCaseGroup(node) : "TestCase" === node.type ? $scope.deleteTestCase(node) : "TestStep" === node.type && $scope.deleteTestStep(node));
    }, $scope.saveNodeName = function(node) {
        node.disableEdit = !0, node.editName != node.name ? "TestPlan" === node.type ? CBTestPlanManager.updateTestPlanName(node).then(function() {
            node.name = node.editName, node.label = node.name, node.edit = !1, node.editName = null;
        }, function(error) {
            $scope.error = "Could not saved the name, please try again";
        }) : "TestCaseGroup" === node.type ? CBTestPlanManager.updateTestCaseGroupName(node).then(function() {
            node.name = node.editName, node.label = node.name, node.edit = !1, node.editName = null;
        }, function(error) {
            $scope.error = "Could not saved the name, please try again";
        }) : "TestCase" === node.type ? CBTestPlanManager.updateTestCaseName(node).then(function() {
            node.name = node.editName, node.label = node.name, node.edit = !1, node.editName = null;
        }, function(error) {
            $scope.error = "Could not saved the name, please try again";
        }) : "TestStep" === node.type && CBTestPlanManager.updateTestStepName(node).then(function() {
            node.name = node.editName, node.label = node.position + "." + node.name, node.editName = null, 
            node.edit = !1;
        }, function(error) {
            $scope.error = "Could not saved the name, please try again";
        }) : (node.edit = !1, node.editName = null);
    }, $scope.publishTestPlan = function() {
        var modalInstance = $modal.open({
            templateUrl: "views/cb/manage/confirm-publish-testplan.html",
            controller: "ConfirmDialogCtrl",
            size: "md",
            backdrop: "static",
            keyboard: !1
        });
        modalInstance.result.then(function(result) {
            result && ($scope.loading = !0, CBTestPlanManager.publishTestPlan($scope.selectedTestCase.id).then(function(result) {
                "SUCCESS" === result.status ? ($scope.selectedScope.key = "GLOBAL", Notification.success({
                    message: "Test Plan successfully published !",
                    templateUrl: "NotificationSuccessTemplate.html",
                    scope: $rootScope,
                    delay: 5e3
                }), $scope.selectScope(), $scope.selectedTP.id = $scope.selectedTestCase.id, $scope.selectTP()) : Notification.error({
                    message: result.message,
                    templateUrl: "NotificationErrorTemplate.html",
                    scope: $rootScope,
                    delay: 1e4
                }), $scope.loading = !1;
            }, function(error) {
                $scope.loading = !1, Notification.error({
                    message: error.data,
                    templateUrl: "NotificationErrorTemplate.html",
                    scope: $rootScope,
                    delay: 1e4
                });
            }));
        });
    }, $scope.unpublishTestPlan = function() {
        var modalInstance = $modal.open({
            templateUrl: "views/cb/manage/confirm-unpublish-testplan.html",
            controller: "ConfirmDialogCtrl",
            size: "md",
            backdrop: "static",
            keyboard: !1
        });
        modalInstance.result.then(function(result) {
            result && ($scope.loading = !0, CBTestPlanManager.unpublishTestPlan($scope.selectedTestCase.id).then(function(result) {
                "SUCCESS" === result.status ? ($scope.selectedScope.key = "USER", Notification.success({
                    message: "Test Plan successfully unpublished !",
                    templateUrl: "NotificationSuccessTemplate.html",
                    scope: $rootScope,
                    delay: 5e3
                }), $scope.selectScope(), $scope.selectedTP.id = $scope.selectedTestCase.id, $scope.selectTP()) : Notification.error({
                    message: result.message,
                    templateUrl: "NotificationErrorTemplate.html",
                    scope: $rootScope,
                    delay: 1e4
                }), $scope.loading = !1;
            }, function(error) {
                $scope.loading = !1, Notification.error({
                    message: error.data,
                    templateUrl: "NotificationErrorTemplate.html",
                    scope: $rootScope,
                    delay: 1e4
                });
            }));
        });
    }, $scope.openUploadTestPlanModal = function() {
        $modalStack.dismissAll("close");
        var modalInstance = $modal.open({
            templateUrl: "views/cb/manage/upload.html",
            controller: "CBUploadCtrl",
            controllerAs: "ctrl",
            windowClass: "upload-modal",
            backdrop: "static",
            keyboard: !1
        });
        modalInstance.result.then(function(result) {
            null != result.id && ($scope.selectedScope.key = "USER", $scope.selectScope(), $scope.selectedTP.id = result.id, 
            $scope.selectTP());
        });
    }, $scope.expandAll = function() {
        $scope.$broadcast("angular-ui-tree:expand-all"), $scope.testCases.forEach(function(node) {
            $scope.collapse(node, !1);
        });
    }, $scope.collapseAll = function() {
        $scope.$broadcast("angular-ui-tree:collapse-all"), $scope.testCases.forEach(function(node) {
            $scope.collapse(node, !0);
        });
    }, $scope.collapse = function(node, mode) {
        node.collapsed, void 0 !== node.children && node.children.length > 0 && node.children.forEach(function(child) {
            $scope.collapse(child);
        });
    }, $rootScope.$on("event:logoutConfirmed", function() {
        $scope.initTestCase();
    }), $rootScope.$on("event:loginConfirmed", function() {
        $scope.initTestCase();
    });
}), angular.module("cb").controller("CBUploadCtrl", [ "$scope", "$http", "$window", "$modal", "$filter", "$rootScope", "$timeout", "StorageService", "TestCaseService", "TestStepService", "FileUploader", "Notification", "$modalInstance", "userInfoService", "CBTestPlanManager", function($scope, $http, $window, $modal, $filter, $rootScope, $timeout, StorageService, TestCaseService, TestStepService, FileUploader, Notification, $modalInstance, userInfoService, CBTestPlanManager) {
    FileUploader.FileSelect.prototype.isEmptyAfterSelection = function() {
        return !0;
    }, $scope.step = 0;
    var zipUploader = $scope.zipUploader = new FileUploader({
        url: "api/cb/management/uploadZip",
        autoUpload: !0
    });
    zipUploader.onBeforeUploadItem = function(fileItem) {
        $scope.error = null, $scope.loading = !0, fileItem.formData.push({
            domain: $rootScope.domain.domain
        });
    }, zipUploader.onCompleteItem = function(fileItem, response, status, headers) {
        $scope.error = null, "FAILURE" == response.status ? ($scope.step = 1, $scope.error = response.message, 
        $scope.loading = !1) : "SUCCESS" === response.status && (void 0 !== response.token ? CBTestPlanManager.saveZip(response.token, $scope.domain.domain).then(function(response) {
            console.log("$scope.loading", $scope.loading), $scope.loading = !1, "FAILURE" == response.status ? ($scope.step = 1, 
            $scope.error = "Could not saved the zip, please try again") : "ADD" === response.action ? (Notification.success({
                message: "Test Plan Added Successfully !",
                templateUrl: "NotificationSuccessTemplate.html",
                scope: $rootScope,
                delay: 5e3
            }), $modalInstance.close({
                id: response.id
            })) : "UPDATE" === response.action && (Notification.success({
                message: "Test Plan Updated Successfully !",
                templateUrl: "NotificationSuccessTemplate.html",
                scope: $rootScope,
                delay: 5e3
            }), $modalInstance.close({
                id: response.id
            }));
        }, function(error) {
            console.log(error), Notification.error({
                message: error.message,
                templateUrl: "NotificationErrorTemplate.html",
                scope: $rootScope,
                delay: 5e3
            }), $scope.loading = !1, $scope.step = 1, $scope.error = "Could not saved the zip, please try again";
        }) : ($scope.step = 1, $scope.error = "Could not saved the zip, no token was received, please try again"));
    }, $scope.gotStep = function(step) {
        $scope.step = step;
    }, $scope.dismissModal = function() {
        $modalInstance.dismiss();
    }, $scope.generateUUID = function() {
        var d = new Date().getTime(), uuid = "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, function(c) {
            var r = (d + 16 * Math.random()) % 16 | 0;
            return d = Math.floor(d / 16), ("x" == c ? r : 3 & r | 8).toString(16);
        });
        return uuid;
    };
} ]), angular.module("cb").controller("UploadCBTokenCheckCtrl", [ "$scope", "$http", "CF", "$window", "$modal", "$filter", "$rootScope", "$timeout", "StorageService", "TestCaseService", "TestStepService", "userInfoService", "Notification", "modalService", "$routeParams", "$location", "CBTestPlanManager", function($scope, $http, CF, $window, $modal, $filter, $rootScope, $timeout, StorageService, TestCaseService, TestStepService, userInfoService, Notification, modalService, $routeParams, $location, CBTestPlanManager) {
    if ($scope.profileCheckToggleStatus = !1, $scope.token = decodeURIComponent($routeParams.x), 
    $scope.auth = decodeURIComponent($routeParams.y), $scope.domain = decodeURIComponent($routeParams.d), 
    void 0 !== $scope.token && "undefined" !== $scope.auth && void 0 !== $scope.domain) userInfoService.isAuthenticated() ? $location.url("/addcbprofiles?x=" + $scope.token + "&d=" + $scope.domain) : $scope.$emit("event:loginRequestWithAuth", $scope.auth, "/addcbprofiles?x=" + $scope.token + "&d=" + $scope.domain); else if (void 0 !== $scope.token && "undefined" === $scope.auth && void 0 !== $scope.domain) {
        var modalInstance = $modal.open({
            templateUrl: "views/cb/manage/savingTestPlanModal.html",
            windowClass: "upload-modal",
            backdrop: "static",
            keyboard: !1
        });
        CBTestPlanManager.saveZip($scope.token, $scope.domain).then(function(response) {
            modalInstance.close(), "FAILURE" == response.status ? (Notification.error({
                message: "An error occured while adding the Test Plan. Please try again or contact the administator for help",
                templateUrl: "NotificationErrorTemplate.html",
                scope: $rootScope,
                delay: 1e4
            }), $scope.error = "Could not saved the zip, please try again", modalInstance.close()) : (Notification.success({
                message: "Test Plan added successfully!",
                templateUrl: "NotificationSuccessTemplate.html",
                scope: $rootScope,
                delay: 5e3
            }), modalInstance.close(), $location.url("/cb?scope=USER&group=" + response.id));
        }, function(error) {
            $scope.error = "Could not saved the zip, please try again", modalInstance.close();
        });
    }
} ]), angular.module("logs").controller("LogCtrl", [ "$scope", "ValidationLogService", "TransportLogService", "$rootScope", "$timeout", function($scope, ValidationLogService, TransportLogService, $rootScope, $timeout) {
    $scope.numberOfValidationLogs = 0, $scope.numberOfTransportLogs = 0, $scope.error = null, 
    $scope.loadingAll = !1, $scope.loadingOne = !1, $scope.currentDate = new Date(), 
    $scope.selectedType = null, $scope.initLogs = function() {
        $scope.loadingAll = !0, $scope.numberOfValidationLogs = 0, $timeout(function() {
            ValidationLogService.getTotalCount($rootScope.domain.domain).then(function(numberOfValidationLogs) {
                $scope.numberOfValidationLogs = numberOfValidationLogs, $scope.loadingAll = !1;
            }, function(error) {
                $scope.loadingAll = !1, $scope.error = "Sorry, Cannot load the logs. Please try again. \n DEBUG:" + error;
            }), $scope.numberOfTransportLogs = 0, TransportLogService.getTotalCount($rootScope.domain.domain).then(function(numberOfTransportLogs) {
                $scope.numberOfTransportLogs = numberOfTransportLogs, $scope.loadingAll = !1;
            }, function(error) {
                $scope.loadingAll = !1, $scope.error = "Sorry, Cannot load the logs. Please try again. \n DEBUG:" + error;
            });
        }, 1e3), $rootScope.$on("logs:decreaseValidationCount", function(event) {
            $scope.numberOfValidationLogs -= 1;
        }), $rootScope.$on("logs:decreaseTransportCount", function(event) {
            $scope.numberOfTransportLogs -= 1;
        });
    }, $scope.selectType = function(type) {
        $scope.selectedType = type;
    };
} ]), angular.module("logs").controller("ValidationLogCtrl", [ "$scope", "ValidationLogService", "Notification", "$modal", "$rootScope", "$timeout", function($scope, ValidationLogService, Notification, $modal, $rootScope, $timeout) {
    $scope.logs = null, $scope.tmpLogs = null, $scope.logDetails = null, $scope.error = null, 
    $scope.loadingAll = !1, $scope.loadingOne = !1, $scope.allLogs = null, $scope.contextType = "*", 
    $scope.userType = "*", $scope.resultType = "*", $scope.initValidationLogs = function() {
        $scope.loadingAll = !0, $timeout(function() {
            ValidationLogService.getAll($rootScope.domain.domain).then(function(logs) {
                $scope.allLogs = logs, $scope.contextType = "*", $scope.userType = "*", $scope.resultType = "*", 
                $scope.filterBy(), $scope.loadingAll = !1;
            }, function(error) {
                $scope.loadingAll = !1, $scope.error = "Sorry, Cannot load the logs. Please try again. \n DEBUG:" + error;
            });
        }, 1e3);
    }, $scope.openLogDetails = function(validationLogItem) {
        $modal.open({
            templateUrl: "ValidationLogDetails.html",
            controller: "ValidationLogDetailsCtrl",
            windowClass: "valueset-modal",
            animation: !1,
            keyboard: !0,
            backdrop: !0,
            resolve: {
                validationLogItem: function() {
                    return validationLogItem;
                }
            }
        });
    }, $scope.filterBy = function() {
        $scope.logs = $scope.filterByResultType($scope.filterByUserType($scope.filterByContextType($scope.allLogs))), 
        $scope.tmpLogs = [].concat($scope.logs);
    }, $scope.filterByContextType = function(inputLogs) {
        return _.filter(inputLogs, function(log) {
            return "*" === $scope.contextType || $scope.contextType === log.testingStage;
        });
    }, $scope.filterByUserType = function(inputLogs) {
        return _.filter(inputLogs, function(log) {
            return "*" === $scope.userType || "AUTH" === $scope.userType && log.userFullname.indexOf("Guest-") === -1 || "NOT_AUTH" === $scope.userType && log.userFullname.indexOf("Guest-") !== -1;
        });
    }, $scope.filterByResultType = function(inputLogs) {
        return _.filter(inputLogs, function(log) {
            return "*" === $scope.resultType || "SUCCESS" === $scope.resultType && log.validationResult || "FAILED" === $scope.resultType && !log.validationResult;
        });
    }, $scope.deleteLog = function(log) {
        ValidationLogService.deleteLog(log.id).then(function(result) {
            $rootScope.$emit("logs:decreaseValidationCount");
            var index = $scope.logs.indexOf(log);
            index > -1 && $scope.logs.splice(index, 1);
        }, function(error) {
            $scope.error = "Sorry, Cannot delete the log. Please try again. \n DEBUG:" + error;
        });
    };
} ]), angular.module("logs").controller("TransportLogCtrl", [ "$scope", "TransportLogService", "Notification", "$modal", "$rootScope", "$timeout", function($scope, TransportLogService, Notification, $modal, $rootScope, $timeout) {
    $scope.logs = null, $scope.tmpLogs = null, $scope.logDetails = null, $scope.error = null, 
    $scope.loadingAll = !1, $scope.loadingOne = !1, $scope.allLogs = null, $scope.selected = {}, 
    $scope.selected.transportType = "*", $scope.selected.protocol = "*", $scope.userType = "*", 
    $scope.transportTypes = [], $scope.protocols = [], $scope.initTransportLogs = function() {
        $scope.loadingAll = !0, $timeout(function() {
            TransportLogService.getAll($rootScope.domain.domain).then(function(logs) {
                $scope.allLogs = logs, $scope.selected.transportType = "*", $scope.selected.protocol = "*", 
                $scope.userType = "*", $scope.protocols = _(logs).chain().flatten().pluck("protocol").unique().value(), 
                $scope.transportTypes = _(logs).chain().flatten().pluck("testingType").unique().value(), 
                $scope.filterBy(), $scope.loadingAll = !1;
            }, function(error) {
                $scope.loadingAll = !1, $scope.error = "Sorry, Cannot load the logs. Please try again. \n DEBUG:" + error;
            });
        }, 1e3);
    }, $scope.openLogDetails = function(transportLogItem) {
        $modal.open({
            templateUrl: "TransportLogDetails.html",
            controller: "TransportLogDetailsCtrl",
            windowClass: "valueset-modal",
            animation: !1,
            keyboard: !0,
            backdrop: !0,
            resolve: {
                transportLogItem: function() {
                    return transportLogItem;
                }
            }
        });
    }, $scope.filterBy = function() {
        $scope.logs = $scope.filterByProtocol($scope.filterByTransportType($scope.filterByUserType($scope.allLogs))), 
        $scope.tmpLogs = [].concat($scope.logs);
    }, $scope.filterByUserType = function(inputLogs) {
        return _.filter(inputLogs, function(log) {
            return "*" === $scope.userType || "AUTH" === $scope.userType && log.userFullname.indexOf("Guest-") === -1 || "NOT_AUTH" === $scope.userType && log.userFullname.indexOf("Guest-") !== -1;
        });
    }, $scope.filterByProtocol = function(inputLogs) {
        return _.filter(inputLogs, function(log) {
            return "*" === $scope.selected.protocol || $scope.selected.protocol === log.protocol;
        });
    }, $scope.filterByTransportType = function(inputLogs) {
        return _.filter(inputLogs, function(log) {
            return "*" === $scope.selected.transportType || $scope.selected.transportType === log.testingType;
        });
    }, $scope.getTransportTypeIcon = function(connType) {
        return "TA_MANUAL" === connType || "SUT_MANUAL" === connType ? "fa fa-wrench" : "SUT_RESPONDER" === connType || "SUT_INITIATOR" === connType ? "fa fa-arrow-right" : "TA_RESPONDER" === connType || "TA_INITIATOR" === connType ? "fa fa-arrow-left" : "fa fa-check-square-o";
    }, $scope.deleteLog = function(log) {
        TransportLogService.deleteLog(log.id).then(function(result) {
            $rootScope.$emit("logs:decreaseTransportCount");
            var index = $scope.logs.indexOf(log);
            index > -1 && $scope.logs.splice(index, 1);
        }, function(error) {
            $scope.error = "Sorry, Cannot delete the log. Please try again. \n DEBUG:" + error;
        });
    };
} ]), angular.module("logs").controller("TransportLogDetailsCtrl", function($scope, $modalInstance, transportLogItem) {
    $scope.transportLogItem = transportLogItem, $scope.close = function() {
        $modalInstance.dismiss("cancel");
    };
}), angular.module("logs").controller("ValidationLogDetailsCtrl", function($scope, $modalInstance, validationLogItem) {
    $scope.validationLogItem = validationLogItem, $scope.segmentErrors = [], Object.keys($scope.validationLogItem.errorCountInSegment).forEach(function(segment) {
        $scope.segmentErrors.push({
            segment: segment,
            errorCount: $scope.validationLogItem.errorCountInSegment[segment]
        });
    }), $scope.tmpSegmentErrors = [].concat($scope.segmentErrors), $scope.close = function() {
        $modalInstance.dismiss("cancel");
    };
}), angular.module("account").controller("UserProfileCtrl", [ "$scope", "$resource", "AccountLoader", "Account", "userInfoService", "$location", "Transport", "Notification", "$modal", function($scope, $resource, AccountLoader, Account, userInfoService, $location, Transport, Notification, $modal) {
    var PasswordChange = $resource("api/accounts/:id/passwordchange", {
        id: "@id"
    });
    $scope.accountpwd = {}, $scope.initModel = function(data) {
        $scope.account = data, $scope.accountOrig = angular.copy($scope.account);
    }, $scope.updateAccount = function() {
        new Account($scope.account).$save().then(function() {}, function(error) {
            Notification.error({
                message: error.data,
                templateUrl: "NotificationErrorTemplate.html",
                scope: $scope,
                delay: 5e4
            });
        }), $scope.accountOrig = angular.copy($scope.account);
    }, $scope.resetForm = function() {
        $scope.account = angular.copy($scope.accountOrig);
    }, $scope.isUnchanged = function(formData) {
        return angular.equals(formData, $scope.accountOrig);
    }, $scope.changePassword = function() {
        var user = new PasswordChange();
        user.username = $scope.account.username, user.password = $scope.accountpwd.currentPassword, 
        user.newPassword = $scope.accountpwd.newPassword, user.id = $scope.account.id, user.$save().then(function(result) {
            $scope.msg = angular.fromJson(result);
        }, function(error) {
            Notification.error({
                message: error.data,
                templateUrl: "NotificationErrorTemplate.html",
                scope: $scope,
                delay: 5e4
            });
        });
    }, $scope.disableAccount = function() {
        $scope.confirmDisable($scope.account);
    }, $scope.confirmDisable = function(accountToDisable) {
        var modalInstance = $modal.open({
            templateUrl: "ConfirmAccountDisableCtrl.html",
            controller: "ConfirmAccountDisableCtrl",
            resolve: {
                accountToDisable: function() {
                    return accountToDisable;
                }
            }
        });
        modalInstance.result.then(function(accountToDelete) {
            console.log("modal success"), userInfoService.setCurrentUser(null), $scope.$emit("event:logoutRequest"), 
            $location.url("/home");
        }, function(cancel) {});
    }, AccountLoader(userInfoService.getAccountID()).then(function(data) {
        $scope.initModel(data), $scope.$$phase || $scope.$apply();
    }, function(error) {
        Notification.error({
            message: error.data,
            templateUrl: "NotificationErrorTemplate.html",
            scope: $scope,
            delay: 5e4
        });
    });
} ]), angular.module("account").controller("UserAccountCtrl", [ "$scope", "$resource", "AccountLoader", "Account", "userInfoService", "$location", "$rootScope", function($scope, $resource, AccountLoader, Account, userInfoService, $location, $rootScope) {
    $scope.accordi = {
        account: !0,
        accounts: !1
    }, $scope.setSubActive = function(id) {
        id && null !== id && ($rootScope.setSubActive(id), $(".accountMgt").hide(), $("#" + id).show());
    }, $scope.initAccount = function() {
        null === $rootScope.subActivePath && ($rootScope.subActivePath = "account"), $scope.setSubActive($rootScope.subActivePath);
    };
} ]), angular.module("account").directive("stDateRange", [ "$timeout", function($timeout) {
    return {
        restrict: "E",
        require: "^stTable",
        scope: {
            before: "=",
            after: "="
        },
        templateUrl: "stDateRange.html",
        link: function(scope, element, attr, table) {
            function open(before) {
                return function($event) {
                    $event.preventDefault(), $event.stopPropagation(), before ? scope.isBeforeOpen = !0 : scope.isAfterOpen = !0;
                };
            }
            var inputs = element.find("input"), inputBefore = angular.element(inputs[0]), inputAfter = angular.element(inputs[1]), predicateName = attr.predicate;
            [ inputBefore, inputAfter ].forEach(function(input) {
                input.bind("blur", function() {
                    var query = {};
                    scope.isBeforeOpen || scope.isAfterOpen || (scope.before && (query.before = scope.before), 
                    scope.after && (query.after = scope.after), scope.$apply(function() {
                        table.search(query, predicateName);
                    }));
                });
            }), scope.openBefore = open(!0), scope.openAfter = open();
        }
    };
} ]).directive("stNumberRange", [ "$timeout", function($timeout) {
    return {
        restrict: "E",
        require: "^stTable",
        scope: {
            lower: "=",
            higher: "="
        },
        templateUrl: "stNumberRange.html",
        link: function(scope, element, attr, table) {
            var inputs = element.find("input"), inputLower = angular.element(inputs[0]), inputHigher = angular.element(inputs[1]), predicateName = attr.predicate;
            [ inputLower, inputHigher ].forEach(function(input, index) {
                input.bind("blur", function() {
                    var query = {};
                    scope.lower && (query.lower = scope.lower), scope.higher && (query.higher = scope.higher), 
                    scope.$apply(function() {
                        table.search(query, predicateName);
                    });
                });
            });
        }
    };
} ]).filter("customFilter", [ "$filter", function($filter) {
    var filterFilter = $filter("filter"), standardComparator = function(obj, text) {
        return text = ("" + text).toLowerCase(), ("" + obj).toLowerCase().indexOf(text) > -1;
    };
    return function(array, expression) {
        function customComparator(actual, expected) {
            var higherLimit, lowerLimit, itemDate, queryDate, isBeforeActivated = expected.before, isAfterActivated = expected.after, isLower = expected.lower, isHigher = expected.higher;
            if (angular.isObject(expected)) {
                if (expected.before || expected.after) try {
                    return !(isBeforeActivated && (higherLimit = expected.before, itemDate = new Date(actual), 
                    queryDate = new Date(higherLimit), itemDate > queryDate)) && !(isAfterActivated && (lowerLimit = expected.after, 
                    itemDate = new Date(actual), queryDate = new Date(lowerLimit), itemDate < queryDate));
                } catch (e) {
                    return !1;
                } else if (isLower || isHigher) return !(isLower && (higherLimit = expected.lower, 
                actual > higherLimit)) && !(isHigher && (lowerLimit = expected.higher, actual < lowerLimit));
                return !0;
            }
            return standardComparator(actual, expected);
        }
        var output = filterFilter(array, expression, customComparator);
        return output;
    };
} ]), angular.module("account").controller("AccountsListCtrl", [ "$scope", "MultiTestersLoader", "MultiSupervisorsLoader", "Account", "$modal", "$resource", "AccountLoader", "userInfoService", "$location", "Notification", function($scope, MultiTestersLoader, MultiSupervisorsLoader, Account, $modal, $resource, AccountLoader, userInfoService, $location, Notification) {
    $scope.tmpAccountList = [].concat($scope.accountList), $scope.account = null, $scope.accountOrig = null, 
    $scope.accountType = "tester", $scope.scrollbarWidth = $scope.getScrollbarWidth(), 
    $scope.checkedAuthorities = [];
    var PasswordChange = $resource("api/accounts/:id/userpasswordchange", {
        id: "@id"
    }), AccountTypeChange = ($resource("api/accounts/:id/approveaccount", {
        id: "@id"
    }), $resource("api/accounts/:id/suspendaccount", {
        id: "@id"
    }), $resource("api/accounts/:id/useraccounttypechange", {
        id: "@id"
    }));
    $scope.msg = null, $scope.accountpwd = {}, $scope.updateAccount = function() {
        new Account($scope.account).$save(function(data) {}, function(error) {
            Notification.error({
                message: error.data,
                templateUrl: "NotificationErrorTemplate.html",
                scope: $scope,
                delay: 5e4
            });
        }), $scope.accountOrig = angular.copy($scope.account);
    }, $scope.resetForm = function() {
        $scope.account = angular.copy($scope.accountOrig);
    }, $scope.isUnchanged = function(formData) {
        return angular.equals(formData, $scope.accountOrig);
    }, $scope.changePassword = function() {
        var user = new PasswordChange();
        user.username = $scope.account.username, user.password = $scope.accountpwd.currentPassword, 
        user.newPassword = $scope.accountpwd.newPassword, user.id = $scope.account.id, user.$save().then(function(result) {
            $scope.msg = angular.fromJson(result);
        }, function(error) {
            Notification.error({
                message: error.data,
                templateUrl: "NotificationErrorTemplate.html",
                scope: $scope,
                delay: 5e4
            });
        });
    }, $scope.authoritiesList = [ "tester", "deployer", "publisher", "admin" ], $scope.toggleCheck = function(auth) {
        $scope.checkedAuthorities.indexOf(auth) === -1 ? $scope.checkedAuthorities.push(auth) : $scope.checkedAuthorities.splice($scope.checkedAuthorities.indexOf(auth), 1);
    }, $scope.saveAccountType = function() {
        var authorityChange = new AccountTypeChange();
        authorityChange.username = $scope.account.username, authorityChange.accountType = $scope.account.accountType, 
        authorityChange.authorities = $scope.checkedAuthorities, authorityChange.id = $scope.account.id, 
        authorityChange.$save().then(function(result) {
            $scope.msg = angular.fromJson(result);
        }, function(error) {
            Notification.error({
                message: error.data,
                templateUrl: "NotificationErrorTemplate.html",
                scope: $scope,
                delay: 5e4
            });
        });
    }, $scope.loadAccounts = function() {
        userInfoService.isAuthenticated() && userInfoService.isAdmin() && ($scope.msg = null, 
        new MultiTestersLoader().then(function(response) {
            $scope.accountList = response, $scope.tmpAccountList = [].concat($scope.accountList);
        }, function(error) {
            Notification.error({
                message: error.data,
                templateUrl: "NotificationErrorTemplate.html",
                scope: $scope,
                delay: 5e4
            });
        }));
    }, $scope.initManageAccounts = function() {
        $scope.loadAccounts();
    }, $scope.selectAccount = function(row) {
        $scope.accountpwd = {}, $scope.account = row, $scope.checkedAuthorities = $scope.account.authorities, 
        $scope.accountOrig = angular.copy($scope.account);
    }, $scope.disableAccount = function() {
        $scope.confirmDelete($scope.account);
    }, $scope.deleteAccount = function() {
        $scope.confirmDelete($scope.account);
    }, $scope.confirmDelete = function(accountToDelete) {
        var modalInstance = $modal.open({
            templateUrl: "ConfirmAccountDeleteCtrl.html",
            controller: "ConfirmAccountDeleteCtrl",
            resolve: {
                accountToDelete: function() {
                    return accountToDelete;
                },
                accountList: function() {
                    return $scope.accountList;
                }
            }
        });
        modalInstance.result.then(function(accountToDelete) {
            var rowIndex = $scope.accountList.indexOf(accountToDelete);
            rowIndex !== -1 && $scope.accountList.splice(rowIndex, 1), $scope.tmpAccountList = [].concat($scope.accountList), 
            $scope.account = null;
        }, function(error) {
            Notification.error({
                message: error.data,
                templateUrl: "NotificationErrorTemplate.html",
                scope: $scope,
                delay: 5e4
            });
        });
    };
} ]), angular.module("account").controller("NotificationsCtrl", [ "$scope", "MultiTestersLoader", "MultiSupervisorsLoader", "Account", "$modal", "$resource", "AccountLoader", "userInfoService", "$location", "Notification", "notificationService", function($scope, MultiTestersLoader, MultiSupervisorsLoader, Account, $modal, $resource, AccountLoader, userInfoService, $location, Notification, notificationService) {
    $scope.mainNot = {}, $scope.notificationList = [], $scope.selectNotification = function(notification) {
        $scope.mainNot = notification;
    }, $scope.newNotification = function() {
        $scope.mainNot = {};
    }, $scope.saveNotification = function(notification) {
        void 0 !== notification.id ? notificationService.updateNotification(notification).then(function(result) {
            "success" === result.type ? Notification.error({
                message: result.text,
                templateUrl: "NotificationSuccessTemplate.html",
                scope: $scope,
                delay: 5e4
            }) : Notification.error({
                message: result.text,
                templateUrl: "NotificationErrorTemplate.html",
                scope: $scope,
                delay: 5e4
            });
        }, function(error) {
            Notification.error({
                message: "Unabled to update a notification.",
                templateUrl: "NotificationErrorTemplate.html",
                scope: $scope,
                delay: 5e4
            });
        }) : notificationService.saveNotification(notification).then(function(result) {
            "success" === result.type ? (Notification.error({
                message: result.text,
                templateUrl: "NotificationSuccessTemplate.html",
                scope: $scope,
                delay: 5e4
            }), $scope.notificationList.unshift(result.data)) : Notification.error({
                message: result.text,
                templateUrl: "NotificationErrorTemplate.html",
                scope: $scope,
                delay: 5e4
            });
        }, function(error) {
            Notification.error({
                message: "Unabled to add a notification.",
                templateUrl: "NotificationErrorTemplate.html",
                scope: $scope,
                delay: 5e4
            });
        });
    }, $scope.getNotificationList = function() {
        notificationService.getAllNotifications().then(function(result) {
            $scope.notificationList = result;
        }, function(error) {
            Notification.error({
                message: "Unabled to load notifications.",
                templateUrl: "NotificationErrorTemplate.html",
                scope: $scope,
                delay: 5e4
            });
        });
    }, $scope.getNotificationList();
} ]), angular.module("account").controller("ConfirmAccountDeleteCtrl", function($scope, $modalInstance, accountToDelete, accountList, Account, Notification) {
    $scope.accountToDelete = accountToDelete, $scope.accountList = accountList, $scope.delete = function() {
        Account.resource().remove({
            id: accountToDelete.id
        }, function() {
            $modalInstance.close($scope.accountToDelete);
        }, function(error) {
            Notification.error({
                message: error.data,
                templateUrl: "NotificationErrorTemplate.html",
                scope: $scope,
                delay: 5e4
            });
        });
    }, $scope.cancel = function() {
        $modalInstance.dismiss("cancel");
    };
}), angular.module("account").controller("ConfirmAccountDisableCtrl", function($scope, $modalInstance, accountToDisable, Account, Notification) {
    $scope.accountToDisable = accountToDisable, $scope.disable = function() {
        Account.disableAccount($scope.accountToDisable.id).then(function(result) {
            $modalInstance.close($scope.accountToDisable.id);
        }, function(error) {
            Notification.error({
                message: "An error occured, unable to disable user.",
                templateUrl: "NotificationErrorTemplate.html",
                scope: $scope,
                delay: 5e4
            });
        });
    }, $scope.cancel = function() {
        $modalInstance.dismiss("cancel");
    };
}), angular.module("account").controller("ForgottenCtrl", [ "$scope", "$resource", "$rootScope", "Notification", function($scope, $resource, $rootScope, Notification) {
    var ForgottenRequest = $resource("api/sooa/accounts/passwordresetrequest");
    $scope.requestResetPassword = function() {
        var resetReq = new ForgottenRequest();
        resetReq.username = $scope.username, resetReq.$save(function() {
            "resetRequestProcessed" === resetReq.text && ($scope.username = "");
        }, function(error) {
            Notification.error({
                message: error.data,
                templateUrl: "NotificationErrorTemplate.html",
                scope: $scope,
                delay: 5e4
            });
        });
    }, $scope.getAppInfo = function() {
        return $rootScope.appInfo;
    };
} ]), angular.module("account").controller("RegistrationCtrl", [ "$scope", "$resource", "$modal", "$location", "$rootScope", "Notification", function($scope, $resource, $modal, $location, $rootScope, Notification) {
    $scope.account = {}, $scope.registered = !1, $scope.agreed = !1;
    var NewAccount = ($resource("api/sooa/usernames/:username", {
        username: "@username"
    }), $resource("api/sooa/emails/:email", {
        email: "@email"
    }), $resource("api/sooa/accounts/register"));
    $scope.registerAccount = function() {
        if ($scope.agreed) {
            var acctToRegister = new NewAccount();
            acctToRegister.accountType = "tester", acctToRegister.employer = $scope.account.employer, 
            acctToRegister.fullName = $scope.account.fullName, acctToRegister.phone = $scope.account.phone, 
            acctToRegister.title = $scope.account.title, acctToRegister.juridiction = $scope.account.juridiction, 
            acctToRegister.username = $scope.account.username, acctToRegister.password = $scope.account.password, 
            acctToRegister.email = $scope.account.email, acctToRegister.signedConfidentialityAgreement = !0, 
            acctToRegister.$save(function() {
                "userAdded" === acctToRegister.text ? ($scope.account = {}, $scope.registered = !0, 
                $location.path("/home"), Notification.success({
                    message: $rootScope.appInfo.registrationSubmittedContent,
                    templateUrl: "NotificationSuccessTemplate.html",
                    scope: $rootScope,
                    delay: 3e4
                })) : $scope.registered = !1;
            }, function() {
                $scope.registered = !1;
            }), $scope.registered = !0;
        }
    }, $scope.getAppInfo = function() {
        return $rootScope.appInfo;
    };
} ]), angular.module("account").controller("RegisterResetPasswordCtrl", [ "$scope", "$resource", "$modal", "$routeParams", "isFirstSetup", "Notification", function($scope, $resource, $modal, $routeParams, isFirstSetup, Notification) {
    $scope.agreed = !1, $scope.displayForm = !0, $scope.isFirstSetup = isFirstSetup, 
    angular.isDefined($routeParams.username) || ($scope.displayForm = !1), "" === $routeParams.username && ($scope.displayForm = !1), 
    angular.isDefined($routeParams.token) || ($scope.displayForm = !1), "" === $routeParams.token && ($scope.displayForm = !1);
    var AcctResetPassword = $resource("api/sooa/accounts/passwordreset", {
        id: "@userId",
        token: "@token"
    });
    $scope.user = {}, $scope.user.username = $routeParams.username, $scope.user.newUsername = $routeParams.username, 
    $scope.user.userId = $routeParams.userId, $scope.user.token = $routeParams.token, 
    $scope.changePassword = function() {
        if ($scope.agreed) {
            var resetAcctPass = new AcctResetPassword($scope.user);
            resetAcctPass.$save(function() {
                $scope.user.password = "", $scope.user.passwordConfirm = "";
            }, function(error) {
                Notification.error({
                    message: error.data,
                    templateUrl: "NotificationErrorTemplate.html",
                    scope: $scope,
                    delay: 5e4
                });
            });
        }
    };
} ]), angular.module("hit-tool-directives").directive("compile", function($compile) {
    return function(scope, element, attrs) {
        scope.$watch(function(scope) {
            return scope.$eval(attrs.compile);
        }, function(value) {
            element.html(value), $compile(element.contents())(scope);
        });
    };
}), angular.module("hit-tool-directives").directive("stRatio", function() {
    return {
        link: function(scope, element, attr) {
            var ratio = +attr.stRatio;
            element.css("width", ratio + "%");
        }
    };
}), angular.module("hit-tool-directives").directive("csSelect", function() {
    return {
        require: "^stTable",
        template: "",
        scope: {
            row: "=csSelect"
        },
        link: function(scope, element, attr, ctrl) {
            element.bind("change", function(evt) {
                scope.$apply(function() {
                    ctrl.select(scope.row, "single");
                });
            }), scope.$watch("row.isSelected", function(newValue, oldValue) {
                newValue === !0 ? element.parent().addClass("st-selected") : element.parent().removeClass("st-selected");
            });
        }
    };
}), angular.module("hit-tool-directives").directive("mypopover", function($compile, $templateCache) {
    return {
        restrict: "A",
        link: function(scope, element, attrs) {
            var popOverContent = $templateCache.get("profileInfo.html"), options = {
                content: popOverContent,
                placement: "bottom",
                html: !0
            };
            $(element).popover(options);
        }
    };
}), angular.module("hit-tool-directives").directive("windowExit", function($window, $templateCache, $http, User) {
    return {
        restrict: "AE",
        compile: function(element, attrs) {
            var myEvent = $window.attachEvent || $window.addEventListener, chkevent = $window.attachEvent ? "onbeforeunload" : "beforeunload";
            myEvent(chkevent, function(e) {
                $templateCache.removeAll();
            });
        }
    };
}), angular.module("hit-tool-directives").directive("msg", [ function() {
    return {
        restrict: "EA",
        replace: !0,
        link: function(scope, element, attrs) {
            var key = attrs.key;
            attrs.keyExpr && scope.$watch(attrs.keyExpr, function(value) {
                key = value, element.text($.i18n.prop(value));
            }), scope.$watch("language()", function(value) {
                element.text($.i18n.prop(key));
            });
        }
    };
} ]), angular.module("hit-tool-directives").directive("loadingTestcases", [ "$http", function($http) {
    return {
        restrict: "E",
        replace: !0,
        template: '<div><div class="overlay"></div><div class="loading"><i class="fa fa-circle-o-notch fa-spin fa-2x "></i><br>Adding test cases...</div></div>',
        link: function(scope, element, attr) {
            scope.$watch("loading", function(val) {
                val ? $(element).show() : $(element).hide();
            });
        }
    };
} ]), angular.module("hit-tool-directives").directive("validatingFiles", [ "$http", function($http) {
    return {
        restrict: "E",
        replace: !0,
        template: '<div><div class="overlay"></div><div class="loading"><i class="fa fa-circle-o-notch fa-spin fa-2x "></i><br>validating files...</div></div>',
        link: function(scope, element, attr) {
            scope.$watch("loading", function(val) {
                val ? $(element).show() : $(element).hide();
            });
        }
    };
} ]), angular.module("hit-tool-directives").directive("selectMin", function() {
    return {
        restrict: "A",
        require: "ngModel",
        scope: {
            ngMin: "="
        },
        link: function($scope, $element, $attrs, ngModelController) {
            ngModelController.$validators.min = function(value) {
                return !value || value >= $scope.ngMin;
            };
        }
    };
}), angular.module("doc").directive("apiDocs", [ function() {
    return {
        restrict: "A",
        templateUrl: "ApiDocs.html",
        replace: !1,
        controller: "ApiDocsCtrl"
    };
} ]), angular.module("doc").directive("testcaseDoc", [ function() {
    return {
        restrict: "A",
        templateUrl: "TestCaseDoc.html",
        replace: !1,
        controller: "TestCaseDocumentationCtrl"
    };
} ]), angular.module("doc").directive("knownIssues", [ function() {
    return {
        restrict: "A",
        templateUrl: "KnownIssues.html",
        replace: !1,
        controller: "KnownIssuesCtrl"
    };
} ]), angular.module("doc").directive("releaseNotes", [ function() {
    return {
        restrict: "A",
        templateUrl: "ReleaseNotes.html",
        replace: !1,
        controller: "ReleaseNotesCtrl"
    };
} ]), angular.module("doc").directive("userDocs", [ function() {
    return {
        restrict: "A",
        templateUrl: "UserDocs.html",
        replace: !1,
        controller: "UserDocsCtrl"
    };
} ]), angular.module("doc").directive("installationGuide", [ function() {
    return {
        restrict: "A",
        templateUrl: "InstallationGuide.html",
        replace: !1,
        controller: "InstallationGuideCtrl"
    };
} ]), angular.module("doc").directive("toolDownloads", [ function() {
    return {
        restrict: "A",
        templateUrl: "ToolDownloadList.html",
        replace: !1,
        controller: "ToolDownloadListCtrl"
    };
} ]), angular.module("doc").controller("DocumentationCtrl", function($scope, $rootScope, $http, $filter, $cookies, $sce, $timeout, userInfoService, StorageService) {
    $scope.status = {
        userDoc: !0
    }, $scope.scrollbarWidth = $rootScope.getScrollbarWidth(), $scope.selectedScope = {
        key: "USER"
    }, $scope.sectionType = {
        key: "app"
    }, $scope.documentsScopes = [], $scope.allDocumentsScopes = [ {
        key: "USER",
        name: "Private"
    }, {
        key: "GLOBAL",
        name: "Public"
    } ], $scope.downloadDocument = function(path) {
        if (null != path) {
            var form = document.createElement("form");
            form.action = "api/documentation/downloadDocument", form.method = "POST", form.target = "_target";
            var input = document.createElement("input");
            input.name = "path", input.value = path, form.appendChild(input), form.style.display = "none", 
            document.body.appendChild(form), form.submit();
        }
    }, $scope.initDocumentation = function() {
        $scope.selectSectionType("app");
    }, $scope.selectScope = function() {
        $scope.error = null, $scope.selectedScope.key && null !== $scope.selectedScope.key && "" !== $scope.selectedScope.key && (StorageService.set("DOC_MANAGE_SELECTED_SCOPE_KEY", $scope.selectedScope.key), 
        $scope.$broadcast("event:doc:scopeChangedEvent", $scope.selectedScope.key, $scope.sectionType.key));
    }, $scope.selectSectionType = function(sectionType) {
        $scope.sectionType.key = sectionType, $scope.documentsScopes = [ $scope.allDocumentsScopes[1] ], 
        $rootScope.isDocumentationManagementSupported() && userInfoService.isAuthenticated() ? ("app" == $scope.sectionType.key && userInfoService.isAdmin() || $rootScope.hasWriteAccess()) && ($scope.documentsScopes = $scope.allDocumentsScopes) : $scope.documentsScopes = [ $scope.allDocumentsScopes[1] ], 
        $scope.selectedScope.key = $scope.documentsScopes[0].key, $scope.selectScope();
    };
}), angular.module("doc").controller("UserDocsCtrl", function($scope, $rootScope, $http, $filter, $cookies, $sce, $timeout, DocumentationManager, StorageService, $modal, Notification, userInfoService) {
    $scope.docs = [], $scope.loading = !0, $scope.error = null, $scope.scrollbarWidth = $rootScope.getScrollbarWidth(), 
    $scope.scope = null, $scope.actionError = null, $scope.type = "USERDOC", $scope.sectionType = "app", 
    $scope.loadDocs = function(scope, domain) {
        $scope.loading = !0, null !== scope && void 0 !== scope || (scope = StorageService.get("DOC_MANAGE_SELECTED_SCOPE_KEY"), 
        scope = scope && null != scope ? scope : "GLOBAL"), $scope.scope = scope, DocumentationManager.getDocuments(domain, scope, $scope.type).then(function(result) {
            $scope.loading = !1, $scope.docs = result;
        }, function(error) {
            $scope.loading = !1, $scope.error = null, $scope.docs = [];
        });
    }, $scope.initDocs = function(scope, wait) {
        "app" !== $scope.sectionType ? $scope.initDomainDocs(scope, wait) : $scope.initAppDocs(scope, wait);
    }, $scope.initDomainDocs = function(scope, wait) {
        $timeout(function() {
            null != $rootScope.domain && $scope.loadDocs(scope, $rootScope.domain.domain, wait);
        }, wait);
    }, $scope.initAppDocs = function(scope, wait) {
        $timeout(function() {
            $scope.loadDocs(scope, "app", wait);
        }, wait);
    }, $scope.isLink = function(path) {
        return path && null != path && path.startsWith("http");
    }, $scope.downloadDocument = function(path) {
        if (null != path) {
            var form = document.createElement("form");
            form.action = "api/documentation/downloadDocument", form.method = "POST", form.target = "_target";
            var input = document.createElement("input");
            input.name = "path", input.value = path, form.appendChild(input), form.style.display = "none", 
            document.body.appendChild(form), form.submit();
        }
    }, $scope.gotToDoc = function(path) {
        if (null != path) {
            var form = document.createElement("form");
            form.action = "api/documentation/downloadDocument", form.method = "POST", form.target = "_target";
            var input = document.createElement("input");
            input.name = "path", input.value = path, form.appendChild(input), form.style.display = "none", 
            document.body.appendChild(form), form.submit();
        }
    }, $scope.initDocs(null, 3e3), $scope.$on("event:doc:scopeChangedEvent", function(event, scope, sectionType) {
        $scope.sectionType = sectionType, $scope.initDocs(scope, 500);
    }), $scope.addDocument = function() {
        $scope.actionError = null;
        var modalInstance = $modal.open({
            templateUrl: "views/documentation/edit-document.html",
            controller: "CreateOrEditDocumentCtrl",
            windowClass: "documentation-upload-modal",
            backdrop: "static",
            keyboard: !1,
            backdropClick: !1,
            resolve: {
                totalNumber: function() {
                    return $scope.docs.length + 1;
                },
                document: function() {
                    var document = {};
                    return document.position = $scope.docs.length + 1, document.type = $scope.type, 
                    document.scope = $scope.scope, document.domain = "app" !== $scope.sectionType ? $rootScope.domain.domain : $scope.sectionType, 
                    document;
                },
                accept: function() {
                    return ".pdf,.html,.doc,.docx,.pptx,.ppt";
                }
            }
        });
        modalInstance.result.then(function(document) {
            document && null != document && (Notification.success({
                message: "Document added successfully !",
                templateUrl: "NotificationSuccessTemplate.html",
                scope: $rootScope,
                delay: 5e3
            }), $scope.initDocs($scope.scope, 100));
        });
    }, $scope.editDocument = function(document) {
        $scope.actionError = null;
        var modalInstance = $modal.open({
            templateUrl: "views/documentation/edit-document.html",
            controller: "CreateOrEditDocumentCtrl",
            windowClass: "documentation-upload-modal",
            backdrop: "static",
            keyboard: !1,
            backdropClick: !1,
            resolve: {
                totalNumber: function() {
                    return $scope.docs.length + 1;
                },
                document: function() {
                    return angular.copy(document);
                },
                accept: function() {
                    return ".pdf,.html,.doc,.docx,.pptx,.ppt";
                }
            }
        });
        modalInstance.result.then(function(document) {
            document && null != document && (Notification.success({
                message: "Document saved successfully !",
                templateUrl: "NotificationSuccessTemplate.html",
                scope: $rootScope,
                delay: 5e3
            }), $scope.initDocs($scope.scope, 100));
        });
    }, $scope.deleteDocument = function(document) {
        $scope.actionError = null;
        var modalInstance = $modal.open({
            templateUrl: "views/documentation/confirm-delete.html",
            controller: "ConfirmDialogCtrl",
            size: "md",
            backdrop: "static",
            keyboard: !1
        });
        modalInstance.result.then(function(result) {
            result && DocumentationManager.deleteDocument(document.id).then(function(result) {
                Notification.success({
                    message: "Document deleted successfully !",
                    templateUrl: "NotificationSuccessTemplate.html",
                    scope: $rootScope,
                    delay: 5e3
                }), $scope.initDocs($scope.scope, 100);
            }, function(error) {
                $scope.actionError = "Sorry, Cannot delete the document. Please try again. \n DEBUG:" + error;
            });
        });
    }, $scope.publishDocument = function(document) {
        $scope.actionError = null;
        var modalInstance = $modal.open({
            templateUrl: "views/documentation/confirm-publish.html",
            controller: "ConfirmDialogCtrl",
            size: "md",
            backdrop: "static",
            keyboard: !1
        });
        modalInstance.result.then(function(result) {
            result && DocumentationManager.publishDocument(document.id).then(function(result) {
                Notification.success({
                    message: "Document published successfully !",
                    templateUrl: "NotificationSuccessTemplate.html",
                    scope: $rootScope,
                    delay: 5e3
                }), $scope.initDocs($scope.scope, 100);
            }, function(error) {
                $scope.actionError = "Sorry, Cannot delete the document. Please try again. \n DEBUG:" + error;
            });
        });
    };
}), angular.module("doc").controller("CreateOrEditDocumentCtrl", function($scope, $modalInstance, DocumentationManager, FileUploader, totalNumber, document, accept) {
    $scope.error = null, $scope.loading = !1, $scope.hasUrl = !1, $scope.totalNumber = totalNumber, 
    $scope.document = document, $scope.uploadedPath = null, $scope.accept = accept, 
    $scope.document.path && $scope.document.path.startsWith("http") ? $scope.hasUrl = !0 : ($scope.uploadedPath = $scope.document.path, 
    $scope.document.path = ""), $scope.positions = function() {
        for (var array = new Array($scope.totalNumber), index = 0; index < array.length; index++) array[index] = index + 1;
        return array;
    }, FileUploader.FileSelect.prototype.isEmptyAfterSelection = function() {
        return !0;
    };
    var documentUploader = $scope.documentUploader = new FileUploader({
        url: "api/documentation/uploadDocument",
        autoUpload: !0
    });
    documentUploader.onBeforeUploadItem = function(fileItem) {
        $scope.error = null, $scope.uploadedPath = null, $scope.loading = !0, fileItem.formData.push({
            domain: $scope.document.domain,
            type: $scope.document.type
        });
    }, documentUploader.onCompleteItem = function(fileItem, response, status, headers) {
        $scope.loading = !1, $scope.error = null, $scope.uploadedPath = null, 0 == response.success ? $scope.error = "Could not upload and process your file.<br>" + response.message : $scope.uploadedPath = response.path;
    }, $scope.noFileFound = function() {
        return !$scope.hasUrl && (null === $scope.uploadedPath || "" === $scope.uploadedPath);
    }, $scope.submit = function() {
        null != $scope.document.title && "" != $scope.document.title && ($scope.error = null, 
        $scope.loading = !0, $scope.hasUrl || null === $scope.uploadedPath || "" === $scope.uploadedPath || ($scope.document.path = $scope.uploadedPath, 
        $scope.document.name = $scope.uploadedPath.split("\\").pop().split("/").pop()), 
        DocumentationManager.saveDocument($scope.document).then(function(result) {
            $scope.loading = !1, $modalInstance.close(result);
        }, function(error) {
            $scope.loading = !1, $scope.error = error;
        }));
    }, $scope.cancel = function() {
        $modalInstance.dismiss("cancel");
    };
}), angular.module("doc").controller("ReleaseNotesCtrl", function($scope, $rootScope, $http, $filter, $cookies, $sce, $timeout, DocumentationManager, StorageService, $modal, Notification) {
    $scope.docs = [], $scope.loading = !1, $scope.error = null, $scope.scrollbarWidth = $rootScope.getScrollbarWidth(), 
    $scope.type = "RELEASENOTE", $scope.sectionType = "app", $scope.scope = null, $scope.loadDocs = function(scope, domain) {
        $scope.loading = !0, null != $rootScope.domain && (null !== scope && void 0 !== scope || (scope = StorageService.get("DOC_MANAGE_SELECTED_SCOPE_KEY"), 
        scope = scope && null != scope ? scope : "GLOBAL"), $scope.scope = scope, DocumentationManager.getDocuments(domain, scope, $scope.type).then(function(result) {
            $scope.loading = !1, $scope.docs = result;
        }, function(error) {
            $scope.loading = !1, $scope.error = null, $scope.docs = [];
        }));
    }, $scope.initDocs = function(scope, wait) {
        "app" !== $scope.sectionType ? $scope.initDomainDocs(scope, wait) : $scope.initAppDocs(scope, wait);
    }, $scope.initDomainDocs = function(scope, wait) {
        $timeout(function() {
            null != $rootScope.domain && $scope.loadDocs(scope, $rootScope.domain.domain, wait);
        }, wait);
    }, $scope.initAppDocs = function(scope, wait) {
        $timeout(function() {
            $scope.loadDocs(scope, "app", wait);
        }, wait);
    }, $scope.downloadDocument = function(path) {
        if (null != path) {
            var form = document.createElement("form");
            form.action = "api/documentation/downloadDocument", form.method = "POST", form.target = "_target";
            var input = document.createElement("input");
            input.name = "path", input.value = path, form.appendChild(input), form.style.display = "none", 
            document.body.appendChild(form), form.submit();
        }
    }, $scope.initDocs(null, 3e3), $scope.$on("event:doc:scopeChangedEvent", function(event, scope, sectionType) {
        $scope.sectionType = sectionType, $scope.initDocs(scope, 500);
    }), $scope.addDocument = function() {
        $scope.actionError = null;
        var modalInstance = $modal.open({
            templateUrl: "views/documentation/edit-document.html",
            controller: "CreateOrEditDocumentCtrl",
            windowClass: "documentation-upload-modal",
            backdrop: "static",
            keyboard: !1,
            backdropClick: !1,
            resolve: {
                totalNumber: function() {
                    return $scope.docs.length + 1;
                },
                document: function() {
                    var document = {};
                    return document.position = $scope.docs.length + 1, document.type = $scope.type, 
                    document.scope = $scope.scope, document.domain = "app" !== $scope.sectionType ? $rootScope.domain.domain : $scope.sectionType, 
                    document;
                },
                accept: function() {
                    return ".pdf,.doc,.docx";
                }
            }
        });
        modalInstance.result.then(function(document) {
            document && null != document && (Notification.success({
                message: "Document added successfully !",
                templateUrl: "NotificationSuccessTemplate.html",
                scope: $rootScope,
                delay: 5e3
            }), $scope.initDocs($scope.scope, 100));
        });
    }, $scope.editDocument = function(document) {
        $scope.actionError = null;
        var modalInstance = $modal.open({
            templateUrl: "views/documentation/edit-document.html",
            controller: "CreateOrEditDocumentCtrl",
            windowClass: "documentation-upload-modal",
            backdrop: "static",
            keyboard: !1,
            backdropClick: !1,
            resolve: {
                totalNumber: function() {
                    return $scope.docs.length + 1;
                },
                document: function() {
                    return angular.copy(document);
                },
                accept: function() {
                    return ".pdf,.doc,.docx";
                }
            }
        });
        modalInstance.result.then(function(document) {
            document && null != document && (Notification.success({
                message: "Document saved successfully !",
                templateUrl: "NotificationSuccessTemplate.html",
                scope: $rootScope,
                delay: 5e3
            }), $scope.initDocs($scope.scope, 100));
        });
    }, $scope.deleteDocument = function(document) {
        $scope.actionError = null;
        var modalInstance = $modal.open({
            templateUrl: "views/documentation/confirm-delete.html",
            controller: "ConfirmDialogCtrl",
            size: "md",
            backdrop: "static",
            keyboard: !1
        });
        modalInstance.result.then(function(result) {
            result && DocumentationManager.deleteDocument(document.id).then(function(result) {
                Notification.success({
                    message: "Document deleted successfully !",
                    templateUrl: "NotificationSuccessTemplate.html",
                    scope: $rootScope,
                    delay: 5e3
                }), $scope.initDocs($scope.scope, 100);
            }, function(error) {
                $scope.actionError = "Sorry, Cannot delete the document. Please try again. \n DEBUG:" + error;
            });
        });
    }, $scope.publishDocument = function(document) {
        $scope.actionError = null;
        var modalInstance = $modal.open({
            templateUrl: "views/documentation/confirm-publish.html",
            controller: "ConfirmDialogCtrl",
            size: "md",
            backdrop: "static",
            keyboard: !1
        });
        modalInstance.result.then(function(result) {
            result && DocumentationManager.publishDocument(document.id).then(function(result) {
                Notification.success({
                    message: "Document published successfully !",
                    templateUrl: "NotificationSuccessTemplate.html",
                    scope: $rootScope,
                    delay: 5e3
                }), $scope.initDocs($scope.scope, 100);
            }, function(error) {
                $scope.actionError = "Sorry, Cannot publish the document. Please try again. \n DEBUG:" + error;
            });
        });
    };
}), angular.module("doc").controller("KnownIssuesCtrl", function($scope, $rootScope, $http, $filter, $cookies, $sce, $timeout, DocumentationManager, StorageService, $modal, Notification) {
    $scope.docs = [], $scope.loading = !1, $scope.error = null, $scope.type = "KNOWNISSUE", 
    $scope.scope = null, $scope.sectionType = "app", $scope.downloadDocument = function(path) {
        if (null != path) {
            var form = document.createElement("form");
            form.action = "api/documentation/downloadDocument", form.method = "POST", form.target = "_target";
            var input = document.createElement("input");
            input.name = "path", input.value = path, form.appendChild(input), form.style.display = "none", 
            document.body.appendChild(form), form.submit();
        }
    }, $scope.loadDocs = function(scope, domain) {
        null != domain && ($scope.loading = !0, null !== scope && void 0 !== scope || (scope = StorageService.get("DOC_MANAGE_SELECTED_SCOPE_KEY"), 
        scope = scope && null != scope ? scope : "GLOBAL"), $scope.scope = scope, DocumentationManager.getDocuments(domain, scope, $scope.type).then(function(result) {
            $scope.loading = !1, $scope.docs = result;
        }, function(error) {
            $scope.loading = !1, $scope.error = null, $scope.docs = [];
        }));
    }, $scope.initDocs = function(scope, wait) {
        "app" !== $scope.sectionType ? $scope.initDomainDocs(scope, wait) : $scope.initAppDocs(scope, wait);
    }, $scope.initDomainDocs = function(scope, wait) {
        $timeout(function() {
            null != $rootScope.domain && $scope.loadDocs(scope, $rootScope.domain.domain, wait);
        }, wait);
    }, $scope.initAppDocs = function(scope, wait) {
        $timeout(function() {
            $scope.loadDocs(scope, "app", wait);
        }, wait);
    }, $scope.initDocs(null, 3e3), $scope.$on("event:doc:scopeChangedEvent", function(event, scope, sectionType) {
        $scope.sectionType = sectionType, $scope.initDocs(scope, 500);
    }), $scope.addDocument = function() {
        $scope.actionError = null;
        var modalInstance = $modal.open({
            templateUrl: "views/documentation/edit-document.html",
            controller: "CreateOrEditDocumentCtrl",
            windowClass: "documentation-upload-modal",
            backdrop: "static",
            keyboard: !1,
            backdropClick: !1,
            resolve: {
                totalNumber: function() {
                    return $scope.docs.length + 1;
                },
                document: function() {
                    var document = {};
                    return document.position = $scope.docs.length + 1, document.type = $scope.type, 
                    document.scope = $scope.scope, document.domain = "app" !== $scope.sectionType ? $rootScope.domain.domain : $scope.sectionType, 
                    document;
                },
                accept: function() {
                    return ".pdf,.doc,.docx";
                }
            }
        });
        modalInstance.result.then(function(document) {
            document && null != document && (Notification.success({
                message: "Document added successfully !",
                templateUrl: "NotificationSuccessTemplate.html",
                scope: $rootScope,
                delay: 5e3
            }), $scope.initDocs($scope.scope, 100));
        });
    }, $scope.editDocument = function(document) {
        $scope.actionError = null;
        var modalInstance = $modal.open({
            templateUrl: "views/documentation/edit-document.html",
            controller: "CreateOrEditDocumentCtrl",
            windowClass: "documentation-upload-modal",
            backdrop: "static",
            keyboard: !1,
            backdropClick: !1,
            resolve: {
                totalNumber: function() {
                    return $scope.docs.length + 1;
                },
                document: function() {
                    return angular.copy(document);
                },
                accept: function() {
                    return ".pdf,.doc,.docx";
                }
            }
        });
        modalInstance.result.then(function(document) {
            document && null != document && (Notification.success({
                message: "Document saved successfully !",
                templateUrl: "NotificationSuccessTemplate.html",
                scope: $rootScope,
                delay: 5e3
            }), $scope.initDocs($scope.scope, 100));
        });
    }, $scope.deleteDocument = function(document) {
        $scope.actionError = null;
        var modalInstance = $modal.open({
            templateUrl: "views/documentation/confirm-delete.html",
            controller: "ConfirmDialogCtrl",
            size: "md",
            backdrop: "static",
            keyboard: !1
        });
        modalInstance.result.then(function(result) {
            result && DocumentationManager.deleteDocument(document.id).then(function(result) {
                Notification.success({
                    message: "Document deleted successfully !",
                    templateUrl: "NotificationSuccessTemplate.html",
                    scope: $rootScope,
                    delay: 5e3
                }), $scope.initDocs($scope.scope, 100);
            }, function(error) {
                $scope.actionError = "Sorry, Cannot delete the document. Please try again. \n DEBUG:" + error;
            });
        });
    }, $scope.publishDocument = function(document) {
        $scope.actionError = null;
        var modalInstance = $modal.open({
            templateUrl: "views/documentation/confirm-publish.html",
            controller: "ConfirmDialogCtrl",
            size: "md",
            backdrop: "static",
            keyboard: !1
        });
        modalInstance.result.then(function(result) {
            result && DocumentationManager.publishDocument(document.id).then(function(result) {
                Notification.success({
                    message: "Document published successfully !",
                    templateUrl: "NotificationSuccessTemplate.html",
                    scope: $rootScope,
                    delay: 5e3
                }), $scope.initDocs($scope.scope, 100);
            }, function(error) {
                $scope.actionError = "Sorry, Cannot publish the document. Please try again. \n DEBUG:" + error;
            });
        });
    };
}), angular.module("doc").controller("ToolDownloadListCtrl", function($scope, $rootScope, $http, $filter, $cookies, $sce, $timeout, DocumentationManager, StorageService, $modal, Notification) {
    $scope.loading = !1, $scope.error = null, $scope.scrollbarWidth = $rootScope.getScrollbarWidth(), 
    $scope.loading = !0, $scope.type = "DELIVERABLE", $scope.scope = null, $scope.actionError = null, 
    $scope.docs = [], $scope.canEdit = !1, $scope.sectionType = "app", $scope.loadDocs = function(scope, domain) {
        null != domain && ($scope.loading = !0, null !== scope && void 0 !== scope || (scope = StorageService.get("DOC_MANAGE_SELECTED_SCOPE_KEY"), 
        scope = scope && null != scope ? scope : "GLOBAL"), $scope.scope = scope, DocumentationManager.getDocuments(domain, scope, $scope.type).then(function(result) {
            $scope.error = null, $scope.docs = result, $scope.loading = !1;
        }, function(error) {
            $scope.loading = !1, $scope.error = "Sorry, failed to load the files", $scope.data = [];
        }));
    }, $scope.initDocs = function(scope, wait) {
        "app" !== $scope.sectionType ? $scope.initDomainDocs(scope, wait) : $scope.initAppDocs(scope, wait);
    }, $scope.initDomainDocs = function(scope, wait) {
        $timeout(function() {
            null != $rootScope.domain && $scope.loadDocs(scope, $rootScope.domain.domain, wait);
        }, wait);
    }, $scope.initAppDocs = function(scope, wait) {
        $timeout(function() {
            $scope.loadDocs(scope, "app", wait);
        }, wait);
    }, $scope.initDocs(null, 3e3), $scope.isLink = function(path) {
        return path && null != path && path.startsWith("http");
    }, $scope.downloadTool = function(path) {
        if (null != path) {
            var form = document.createElement("form");
            form.action = "api/documentation/downloadDocument", form.method = "POST", form.target = "_target";
            var input = document.createElement("input");
            input.name = "path", input.value = path, form.appendChild(input), form.style.display = "none", 
            document.body.appendChild(form), form.submit();
        }
    }, $scope.$on("event:doc:scopeChangedEvent", function(event, scope, sectionType) {
        $scope.sectionType = sectionType, $scope.initDocs(scope, 500);
    }), $scope.isLink = function(path) {
        return path && null != path && path.startsWith("http");
    }, $scope.downloadDocument = function(path) {
        if (null != path) {
            var form = document.createElement("form");
            form.action = "api/documentation/downloadDocument", form.method = "POST", form.target = "_target";
            var input = document.createElement("input");
            input.name = "path", input.value = path, form.appendChild(input), form.style.display = "none", 
            document.body.appendChild(form), form.submit();
        }
    }, $scope.addDocument = function() {
        $scope.actionError = null;
        var modalInstance = $modal.open({
            templateUrl: "views/documentation/edit-document.html",
            controller: "CreateOrEditDocumentCtrl",
            windowClass: "documentation-upload-modal",
            backdrop: "static",
            keyboard: !1,
            backdropClick: !1,
            resolve: {
                totalNumber: function() {
                    return $scope.docs.length + 1;
                },
                document: function() {
                    var document = {};
                    return document.position = $scope.docs.length + 1, document.type = $scope.type, 
                    document.scope = $scope.scope, document.domain = "app" !== $scope.sectionType ? $rootScope.domain.domain : $scope.sectionType, 
                    document;
                },
                accept: function() {
                    return ".zip";
                }
            }
        });
        modalInstance.result.then(function(document) {
            document && null != document && (Notification.success({
                message: "Document added successfully !",
                templateUrl: "NotificationSuccessTemplate.html",
                scope: $rootScope,
                delay: 5e3
            }), $scope.initDocs($scope.scope, 100));
        });
    }, $scope.editDocument = function(document) {
        $scope.actionError = null;
        var modalInstance = $modal.open({
            templateUrl: "views/documentation/edit-document.html",
            controller: "CreateOrEditDocumentCtrl",
            windowClass: "documentation-upload-modal",
            backdrop: "static",
            keyboard: !1,
            backdropClick: !1,
            resolve: {
                totalNumber: function() {
                    return $scope.docs.length + 1;
                },
                document: function() {
                    return angular.copy(document);
                },
                accept: function() {
                    return ".zip";
                }
            }
        });
        modalInstance.result.then(function(document) {
            document && null != document && (Notification.success({
                message: "Document saved successfully !",
                templateUrl: "NotificationSuccessTemplate.html",
                scope: $rootScope,
                delay: 5e3
            }), $scope.initDocs($scope.scope, 100));
        });
    }, $scope.deleteDocument = function(document) {
        $scope.actionError = null;
        var modalInstance = $modal.open({
            templateUrl: "views/documentation/confirm-delete.html",
            controller: "ConfirmDialogCtrl",
            size: "md",
            backdrop: "static",
            keyboard: !1
        });
        modalInstance.result.then(function(result) {
            result && DocumentationManager.deleteDocument(document.id).then(function(result) {
                Notification.success({
                    message: "Document deleted successfully !",
                    templateUrl: "NotificationSuccessTemplate.html",
                    scope: $rootScope,
                    delay: 5e3
                }), $scope.initDocs($scope.scope, 100);
            }, function(error) {
                $scope.actionError = "Sorry, Cannot delete the document. Please try again. \n DEBUG:" + error;
            });
        });
    }, $scope.publishDocument = function(document) {
        $scope.actionError = null;
        var modalInstance = $modal.open({
            templateUrl: "views/documentation/confirm-publish.html",
            controller: "ConfirmDialogCtrl",
            size: "md",
            backdrop: "static",
            keyboard: !1
        });
        modalInstance.result.then(function(result) {
            result && DocumentationManager.publishDocument(document.id).then(function(result) {
                Notification.success({
                    message: "Document published successfully !",
                    templateUrl: "NotificationSuccessTemplate.html",
                    scope: $rootScope,
                    delay: 5e3
                }), $scope.initDocs($scope.scope, 100);
            }, function(error) {
                $scope.actionError = "Sorry, Cannot publish the document. Please try again. \n DEBUG:" + error;
            });
        });
    };
}), angular.module("doc").controller("ApiDocsCtrl", function($scope, $rootScope, $http, $filter, $cookies, $sce, $timeout, $window, StorageService) {
    $scope.data = [], $scope.loading = !1, $scope.error = null, $scope.scrollbarWidth = $rootScope.getScrollbarWidth(), 
    $scope.apiLink = function() {
        return $rootScope.apiLink;
    };
}), angular.module("doc").controller("InstallationGuideCtrl", function($scope, $rootScope, $http, $filter, $cookies, $sce, $timeout, DocumentationManager, StorageService, $modal, Notification) {
    $scope.docs = [], $scope.loading = !1, $scope.error = null, $scope.scope = null, 
    $scope.loading = !1, $scope.scope = null, $scope.type = "INSTALLATION", $scope.sectionType = "app", 
    $scope.loadDocs = function(scope, domain) {
        null != domain && ($scope.loading = !0, null !== scope && void 0 !== scope || (scope = StorageService.get("DOC_MANAGE_SELECTED_SCOPE_KEY"), 
        scope = scope && null != scope ? scope : "GLOBAL"), $scope.scope = scope, DocumentationManager.getDocuments(domain, scope, $scope.type).then(function(result) {
            $scope.error = null, $scope.docs = result, $scope.loading = !1;
        }, function(error) {
            $scope.loading = !1, $scope.error = "Sorry, failed to load the files", $scope.data = [];
        }));
    }, $scope.initDocs = function(scope, wait) {
        "app" !== $scope.sectionType ? $scope.initDomainDocs(scope, wait) : $scope.initAppDocs(scope, wait);
    }, $scope.initDomainDocs = function(scope, wait) {
        $timeout(function() {
            null != $rootScope.domain && $scope.loadDocs(scope, $rootScope.domain.domain, wait);
        }, wait);
    }, $scope.initAppDocs = function(scope, wait) {
        $timeout(function() {
            $scope.loadDocs(scope, "app", wait);
        }, wait);
    }, $scope.initDocs(null, 3e3), $scope.$on("event:doc:scopeChangedEvent", function(event, scope, sectionType) {
        $scope.sectionType = sectionType, $scope.initDocs(scope, 500);
    }), $scope.isLink = function(path) {
        return path && null != path && path.startsWith("http");
    }, $scope.downloadDocument = function(path) {
        if (null != path) {
            var form = document.createElement("form");
            form.action = "api/documentation/downloadDocument", form.method = "POST", form.target = "_target";
            var input = document.createElement("input");
            input.name = "path", input.value = path, form.appendChild(input), form.style.display = "none", 
            document.body.appendChild(form), form.submit();
        }
    }, $scope.addDocument = function() {
        $scope.actionError = null;
        var modalInstance = $modal.open({
            templateUrl: "views/documentation/edit-document.html",
            controller: "CreateOrEditDocumentCtrl",
            windowClass: "documentation-upload-modal",
            backdrop: "static",
            keyboard: !1,
            backdropClick: !1,
            resolve: {
                totalNumber: function() {
                    return $scope.docs.length + 1;
                },
                document: function() {
                    var document = {};
                    return document.position = $scope.docs.length + 1, document.type = $scope.type, 
                    document.scope = $scope.scope, document.domain = "app" !== $scope.sectionType ? $rootScope.domain.domain : $scope.sectionType, 
                    document;
                },
                accept: function() {
                    return ".pdf,.doc,.docx,.pptx,.ppt";
                }
            }
        });
        modalInstance.result.then(function(document) {
            document && null != document && (Notification.success({
                message: "Document added successfully !",
                templateUrl: "NotificationSuccessTemplate.html",
                scope: $rootScope,
                delay: 5e3
            }), $scope.initDocs($scope.scope, 100));
        });
    }, $scope.editDocument = function(document) {
        $scope.actionError = null;
        var modalInstance = $modal.open({
            templateUrl: "views/documentation/edit-document.html",
            controller: "CreateOrEditDocumentCtrl",
            windowClass: "documentation-upload-modal",
            backdrop: "static",
            keyboard: !1,
            backdropClick: !1,
            resolve: {
                totalNumber: function() {
                    return $scope.docs.length + 1;
                },
                document: function() {
                    return angular.copy(document);
                },
                accept: function() {
                    return ".pdf,.doc,.docx,.pptx,.ppt";
                }
            }
        });
        modalInstance.result.then(function(document) {
            document && null != document && (Notification.success({
                message: "Document saved successfully !",
                templateUrl: "NotificationSuccessTemplate.html",
                scope: $rootScope,
                delay: 5e3
            }), $scope.initDocs($scope.scope, 100));
        });
    }, $scope.deleteDocument = function(document) {
        $scope.actionError = null;
        var modalInstance = $modal.open({
            templateUrl: "views/documentation/confirm-delete.html",
            controller: "ConfirmDialogCtrl",
            size: "md",
            backdrop: "static",
            keyboard: !1
        });
        modalInstance.result.then(function(result) {
            result && DocumentationManager.deleteDocument(document.id).then(function(result) {
                Notification.success({
                    message: "Document deleted successfully !",
                    templateUrl: "NotificationSuccessTemplate.html",
                    scope: $rootScope,
                    delay: 5e3
                }), $scope.initDocs($scope.scope, 100);
            }, function(error) {
                $scope.actionError = "Sorry, Cannot delete the document. Please try again. \n DEBUG:" + error;
            });
        });
    }, $scope.publishDocument = function(document) {
        $scope.actionError = null;
        var modalInstance = $modal.open({
            templateUrl: "views/documentation/confirm-publish.html",
            controller: "ConfirmDialogCtrl",
            size: "md",
            backdrop: "static",
            keyboard: !1
        });
        modalInstance.result.then(function(result) {
            result && DocumentationManager.publishDocument(document.id).then(function(result) {
                Notification.success({
                    message: "Document published successfully !",
                    templateUrl: "NotificationSuccessTemplate.html",
                    scope: $rootScope,
                    delay: 5e3
                }), $scope.initDocs($scope.scope, 100);
            }, function(error) {
                $scope.actionError = "Sorry, Cannot publish the document. Please try again. \n DEBUG:" + error;
            });
        });
    };
}), angular.module("doc").controller("TestCaseDocumentationCtrl", function($scope, $rootScope, $http, $filter, $cookies, $sce, $timeout, DocumentationManager, ngTreetableParams, StorageService, Notification) {
    $scope.context = null, $scope.data = null, $scope.loading = !1, $scope.scrollbarWidth = $rootScope.getScrollbarWidth(), 
    $scope.error = null, $scope.error = null, $scope.tree = {}, $scope.sectionType = "app", 
    $scope.loadDocs = function(scope, domain) {
        $scope.loading = !0, null !== scope && void 0 !== scope || (scope = StorageService.get("DOC_MANAGE_SELECTED_SCOPE_KEY"), 
        scope = scope && null != scope ? scope : "GLOBAL"), $scope.scope = scope, $scope.domain = domain, 
        $rootScope.isDomainSelectionSupported() || 1 !== $rootScope.appInfo.domains.length || ($scope.domain = $rootScope.appInfo.domains[0].domain), 
        DocumentationManager.getTestCaseDocuments($scope.domain, "GLOBALANDUSER").then(function(data) {
            if ($scope.error = null, $scope.context = data, $scope.data = [], null != data) for (var index = 0; index < data.length; index++) $scope.data.push(angular.fromJson($scope.context[index].json));
            $scope.params.refresh(), $scope.loading = !1;
        }, function(error) {
            $scope.loading = !1, $scope.error = "Sorry, failed to load the documents";
        });
    }, $scope.initDocs = function(scope, wait) {
        "app" !== $scope.sectionType ? $scope.initDomainDocs(scope, wait) : $scope.initAppDocs(scope, wait);
    }, $scope.initDomainDocs = function(scope, wait) {
        $timeout(function() {
            null != $rootScope.domain && $scope.loadDocs(scope, $rootScope.domain.domain, wait);
        }, wait);
    }, $scope.initAppDocs = function(scope, wait) {
        $timeout(function() {
            $scope.loadDocs(scope, "app", wait);
        }, wait);
    }, $scope.initDocs(null, 3e3), $scope.$on("event:doc:scopeChangedEvent", function(event, scope, sectionType) {
        $scope.sectionType = sectionType, $scope.initDocs(scope, 500);
    }), $scope.params = new ngTreetableParams({
        getNodes: function(parent) {
            return parent ? parent.children : null != $scope.data ? $scope.data : [];
        },
        getTemplate: function(node) {
            return "TestCaseDocumentationNode.html";
        },
        options: {
            initialState: "expanded"
        }
    }), $scope.downloadCompleteTestPackage = function(stage) {
        if (null != stage && null != $scope.scope && null != $scope.domain) {
            var form = document.createElement("form");
            form.action = "api/documentation/testPackages", form.method = "POST", form.target = "_target";
            var input = document.createElement("input");
            input.name = "stage", input.value = stage, form.appendChild(input), input = document.createElement("input"), 
            input.name = "domain", input.value = $scope.domain, form.appendChild(input), input = document.createElement("input"), 
            input.name = "scope", input.value = $scope.scope, form.appendChild(input), form.style.display = "none", 
            document.body.appendChild(form), form.submit();
        }
    }, $scope.downloadExampleMessages = function(stage) {
        if (null != stage && null != $scope.scope && null != $scope.domain) {
            var form = document.createElement("form");
            form.action = "api/documentation/exampleMessages", form.method = "POST", form.target = "_target";
            var input = document.createElement("input");
            input.name = "stage", input.value = stage, form.appendChild(input), input = document.createElement("input"), 
            input.name = "domain", input.value = $scope.domain, form.appendChild(input), input = document.createElement("input"), 
            input.name = "scope", input.value = $scope.scope, form.appendChild(input), form.style.display = "none", 
            document.body.appendChild(form), form.submit();
        }
    }, $scope.downloadArtifact = function(path, title) {
        if (null != path && title) {
            var form = document.createElement("form");
            form.action = "api/documentation/artifact", form.method = "POST", form.target = "_target";
            var input = document.createElement("input");
            input.name = "path", input.value = path, form.appendChild(input), input = document.createElement("input"), 
            input.name = "title", input.value = title, form.appendChild(input), form.style.display = "none", 
            document.body.appendChild(form), form.submit();
        }
    }, $scope.formatUrl = function(format) {
        return "api/" + format + "/documentation/";
    }, $scope.downloadMessage = function(row) {
        $scope.downloadContextFile(row.id, row.type, $scope.formatUrl(row.format) + "message.txt", row.title);
    }, $scope.downloadProfile = function(row) {
        $scope.downloadContextFile(row.id, row.type, $scope.formatUrl(row.format) + "profile.xml", row.title);
    }, $scope.downloadValueSetLib = function(row) {
        $scope.downloadContextFile(row.id, row.type, $scope.formatUrl(row.format) + "valueset.xml", row.title);
    }, $scope.downloadConstraints = function(row) {
        $scope.downloadContextFile(row.id, row.type, $scope.formatUrl(row.format) + "constraints.zip", row.title);
    }, $scope.downloadCoConstraints = function(row) {
        $scope.downloadContextFile(row.id, row.type, $scope.formatUrl(row.format) + "coconstraints.xml", row.title);
    }, $scope.downloadValueSetBindings = function(row) {
        $scope.downloadContextFile(row.id, row.type, $scope.formatUrl(row.format) + "valuesetbindings.xml", row.title);
    }, $scope.downloadSlicings = function(row) {
        $scope.downloadContextFile(row.id, row.type, $scope.formatUrl(row.format) + "slicings.xml", row.title);
    }, $scope.downloadContextFile = function(targetId, targetType, targetUrl, targetTitle) {
        if (null != targetId && null != targetType && null != targetUrl) {
            var form = document.createElement("form");
            form.action = targetUrl, form.method = "POST", form.target = "_target";
            var input = document.createElement("input");
            input.name = "targetId", input.value = targetId, form.appendChild(input), input = document.createElement("input"), 
            input.name = "targetType", input.value = targetType, form.appendChild(input), input = document.createElement("input"), 
            input.name = "targetTitle", input.value = targetTitle, form.appendChild(input), 
            form.style.display = "none", document.body.appendChild(form), form.submit();
        }
    }, $scope.downloadDocument = function(path) {
        if (null != path) {
            var form = document.createElement("form");
            form.action = "api/documentation/downloadDocument", form.method = "POST", form.target = "_target";
            var input = document.createElement("input");
            input.name = "path", input.value = path, form.appendChild(input), form.style.display = "none", 
            document.body.appendChild(form), form.submit();
        }
    };
}), angular.module("account").directive("checkEmail", [ "$resource", function($resource) {
    return {
        restrict: "AC",
        require: "ngModel",
        link: function(scope, element, attrs, ctrl) {
            var Email = $resource("api/sooa/emails/:email", {
                email: "@email"
            }), EMAIL_REGEXP = /^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,4}$/;
            element.on("keyup", function() {
                if (0 !== element.val().length && EMAIL_REGEXP.test(element.val())) {
                    var emailToCheck = new Email({
                        email: element.val()
                    });
                    emailToCheck.$get(function() {
                        scope.emailUnique = "emailNotFound" === emailToCheck.text ? "valid" : void 0, scope.emailValid = EMAIL_REGEXP.test(element.val()) ? "valid" : void 0, 
                        scope.emailUnique && scope.emailValid ? ctrl.$setValidity("email", !0) : ctrl.$setValidity("email", !1);
                    }, function() {});
                } else scope.emailUnique = void 0, scope.emailValid = void 0, ctrl.$setValidity("email", !1);
            });
        }
    };
} ]), angular.module("account").directive("checkEmployer", [ function() {
    return {
        require: "ngModel",
        link: function(scope, elem, attrs, ctrl) {
            var employer = "#" + attrs.checkEmployer;
            elem.add(employer).on("keyup", function() {
                scope.$apply(function() {
                    var v = elem.val() === $(firstPassword).val();
                    ctrl.$setValidity("noMatch", v);
                });
            });
        }
    };
} ]), angular.module("account").directive("checkPassword", [ function() {
    return {
        require: "ngModel",
        link: function(scope, elem, attrs, ctrl) {
            var firstPassword = "#" + attrs.checkPassword;
            elem.add(firstPassword).on("keyup", function() {
                scope.$apply(function() {
                    var v = elem.val() === $(firstPassword).val();
                    ctrl.$setValidity("noMatch", v);
                });
            });
        }
    };
} ]), angular.module("account").directive("checkPhone", [ function() {
    return {
        restrict: "AC",
        require: "ngModel",
        link: function(scope, element, attrs, ctrl) {
            var NUMBER_REGEXP = /[0-9]*/;
            element.on("keyup", function() {
                element.val() && null != element.val() && "" != element.val() ? (scope.phoneIsNumber = NUMBER_REGEXP.test(element.val()) && element.val() > 0 ? "valid" : void 0, 
                scope.phoneValidLength = element.val().length >= 7 ? "valid" : void 0, scope.phoneIsNumber && scope.phoneValidLength ? ctrl.$setValidity("phone", !0) : ctrl.$setValidity("phone", !1)) : (scope.phoneIsNumber = void 0, 
                scope.phoneValidLength = void 0, ctrl.$setValidity("phone", !0));
            });
        }
    };
} ]), angular.module("account").directive("checkPoaDate", [ function() {
    return {
        replace: !0,
        link: function(scope, elem, attrs, ctrl) {
            var startElem = elem.find("#inputStartDate"), endElem = elem.find("#inputEndDate"), ctrlStart = startElem.inheritedData().$ngModelController, ctrlEnd = endElem.inheritedData().$ngModelController, checkDates = function() {
                var sDate = new Date(startElem.val()), eDate = new Date(endElem.val());
                sDate < eDate ? (ctrlStart.$setValidity("datesOK", !0), ctrlEnd.$setValidity("datesOK", !0)) : (ctrlStart.$setValidity("datesOK", !1), 
                ctrlEnd.$setValidity("datesOK", !1));
            };
            startElem.on("change", checkDates), endElem.on("change", checkDates);
        }
    };
} ]), angular.module("account").directive("checkTimerange", [ function() {
    return {
        replace: !0,
        link: function(scope, elem, attrs, ctrl) {
            var ctrlSH, ctrlSM, ctrlEH, ctrlEM, myElem = elem.children(), sh = myElem.find(".shour"), sm = myElem.find(".sminute"), eh = myElem.find(".ehour"), em = myElem.find(".eminute");
            ctrlSH = sh.inheritedData().$ngModelController, ctrlSM = sm.inheritedData().$ngModelController, 
            ctrlEH = eh.inheritedData().$ngModelController, ctrlEM = em.inheritedData().$ngModelController;
            var newnew = !0, checkTimeRange = function() {
                newnew && (ctrlSH.$setViewValue(ctrlSH.$modelValue), ctrlSM.$setViewValue(ctrlSM.$modelValue), 
                ctrlEH.$setViewValue(ctrlEH.$modelValue), ctrlEM.$setViewValue(ctrlEM.$modelValue), 
                newnew = !1);
                var tmpDate = new Date(), startTime = angular.copy(tmpDate), endTime = angular.copy(tmpDate);
                startTime.setHours(sh.val()), startTime.setMinutes(sm.val()), endTime.setHours(eh.val()), 
                endTime.setMinutes(em.val()), startTime < endTime ? (ctrlSH.$setValidity("poaOK", !0), 
                ctrlSM.$setValidity("poaOK", !0), ctrlEH.$setValidity("poaOK", !0), ctrlEM.$setValidity("poaOK", !0)) : (ctrlSH.$setValidity("poaOK", !1), 
                ctrlSM.$setValidity("poaOK", !1), ctrlEH.$setValidity("poaOK", !1), ctrlEM.$setValidity("poaOK", !1));
            };
            sh.on("change", checkTimeRange), sm.on("change", checkTimeRange), eh.on("change", checkTimeRange), 
            em.on("change", checkTimeRange);
        }
    };
} ]), angular.module("account").directive("checkUsername", [ "$resource", function($resource) {
    return {
        restrict: "AC",
        require: "ngModel",
        link: function(scope, element, attrs, ctrl) {
            var Username = $resource("api/sooa/usernames/:username", {
                username: "@username"
            });
            element.on("keyup", function() {
                if (element.val().length >= 4) {
                    var usernameToCheck = new Username({
                        username: element.val()
                    });
                    usernameToCheck.$get(function() {
                        scope.usernameValidLength = element.val() && element.val().length >= 4 && element.val().length <= 20 ? "valid" : void 0, 
                        scope.usernameUnique = "usernameNotFound" === usernameToCheck.text ? "valid" : void 0, 
                        scope.usernameValidLength && scope.usernameUnique ? ctrl.$setValidity("username", !0) : ctrl.$setValidity("username", !1);
                    }, function() {});
                } else scope.usernameValidLength = void 0, scope.usernameUnique = void 0, ctrl.$setValidity("username", !1);
            });
        }
    };
} ]), angular.module("account").directive("passwordValidate", [ function() {
    return {
        require: "ngModel",
        link: function(scope, elm, attrs, ctrl) {
            ctrl.$parsers.unshift(function(viewValue) {
                return scope.pwdValidLength = viewValue && viewValue.length >= 7 ? "valid" : void 0, 
                scope.pwdHasLowerCaseLetter = viewValue && /[a-z]/.test(viewValue) ? "valid" : void 0, 
                scope.pwdHasUpperCaseLetter = viewValue && /[A-Z]/.test(viewValue) ? "valid" : void 0, 
                scope.pwdHasNumber = viewValue && /\d/.test(viewValue) ? "valid" : void 0, scope.pwdValidLength && scope.pwdHasLowerCaseLetter && scope.pwdHasUpperCaseLetter && scope.pwdHasNumber ? (ctrl.$setValidity("pwd", !0), 
                viewValue) : void ctrl.$setValidity("pwd", !1);
            });
        }
    };
} ]), angular.module("domains").controller("DomainsCtrl", function($scope, $rootScope, $http, $filter, $cookies, $sce, $timeout, userInfoService, StorageService, DomainsManager, $modal, $location, $window) {
    $scope.status = {
        userDoc: !0
    }, $scope.selectedDomain = {
        id: null
    }, $scope.userDomains = null, $scope.userDomain = null, $scope.alertMessage = null, 
    $scope.loading = !1, $scope.loadingDomain = !1, $scope.loadingAction = !1, $scope.loadingDomains = !1, 
    $scope.domainsErrors = null, $scope.getAppInfo = function() {
        return $rootScope.appInfo;
    }, $scope.getAppURL = function() {
        return $rootScope.appInfo.url;
    }, $scope.hasDomainAccess = function(domain) {
        return userInfoService.isAuthenticated() && (userInfoService.isAdmin() || null != domain && domain.owner === userInfoService.getUsername());
    }, $scope.initDomain = function() {
        $scope.loadDomains();
    }, $scope.viewDomain = function(domain, waitingTime) {
        waitingTime = void 0 == waitingTime ? 1e3 : waitingTime, $scope.loadingDomain = !0, 
        $scope.errorDomain = null, $scope.originalUserDomain = null, $scope.userDomain = null, 
        $timeout(function() {
            $rootScope.isDomainsManagementSupported() && userInfoService.isAuthenticated() && null != domain && $scope.hasDomainAccess(domain) ? ($scope.userDomain = null, 
            $scope.errorDomain = null, $scope.userDomain = angular.copy(domain), $scope.originalUserDomain = angular.copy($scope.userDomain), 
            $scope.loadingDomain = !1) : $scope.loadingDomain = !1;
        }, waitingTime);
    }, $scope.getDomainUrl = function(domain) {
        return $scope.getAppURL() + "/#/?d=" + domain.options.DOMAIN_CUSTOM_URL;
    }, $scope.displayScope = function(scope) {
        return "GLOBAL" === scope ? "Public" : "Private";
    }, $scope.loadDomains = function() {
        $scope.userDomains = null, $scope.loadingDomains = !0, $scope.domainsError = null, 
        DomainsManager.findByUserAndRole().then(function(domains) {
            if ($scope.userDomains = domains, $scope.userDomains = $filter("orderBy")($scope.userDomains, "position"), 
            $scope.loadingDomains = !1, null != $scope.userDomains && $scope.userDomains.length > 0) {
                var dom = null;
                if (1 === $scope.userDomains.length) dom = $scope.userDomains[0]; else for (var i = 0; i < $scope.userDomains.length; i++) if ($scope.userDomains[i].domain === $rootScope.domain.domain) {
                    dom = $scope.userDomains[i];
                    break;
                }
                null != dom && $scope.viewDomain(dom);
            }
        }, function(error) {
            $scope.loadingDomains = !1, $scope.domainsError = error;
        });
    }, $scope.closeAlert = function() {
        $scope.alertMessage = null;
    }, $scope.setErrorAlert = function(message) {
        $scope.alertMessage = {}, $scope.alertMessage.type = "danger", $scope.alertMessage.message = message;
    }, $scope.setInfoAlert = function(message) {
        $scope.alertMessage = {}, $scope.alertMessage.type = "info", $scope.alertMessage.message = message;
    }, $scope.setSuccessAlert = function(message) {
        $scope.alertMessage = {}, $scope.alertMessage.type = "success", $scope.alertMessage.message = message;
    }, $scope.deleteDomain = function() {
        var modalInstance = $modal.open({
            templateUrl: "views/domains/confirm-delete.html",
            controller: "ConfirmDialogCtrl",
            size: "md",
            backdrop: "static",
            keyboard: !1
        });
        modalInstance.result.then(function(result) {
            result && DomainsManager.delete($scope.userDomain.id).then(function(response) {
                $scope.userDomain = null, $scope.originalUserDomain = null, $scope.loadingAction = !1, 
                $scope.setSuccessAlert("Tool scope deleted successfully!"), $rootScope.domain = null, 
                $rootScope.reloadPage();
            }, function(error) {
                $scope.loadingAction = !1, $scope.setErrorAlert(error.text);
            });
        });
    }, $scope.saveDomain = function() {
        $scope.loadingAction = !0, DomainsManager.save($scope.userDomain).then(function(result) {
            $scope.userDomain = result, $scope.originalUserDomain = angular.copy(result), $scope.loadingAction = !1, 
            $scope.setSuccessAlert("Tool scope saved successfully!"), $rootScope.domain = angular.copy(result), 
            $rootScope.reloadPage();
        }, function(error) {
            $scope.loadingAction = !1, $scope.setErrorAlert(error.text);
        });
    }, $scope.resetDomain = function() {
        var modalInstance = $modal.open({
            templateUrl: "views/domains/confirm-reset.html",
            controller: "ConfirmDialogCtrl",
            size: "md",
            backdrop: "static",
            keyboard: !1
        });
        modalInstance.result.then(function(result) {
            result && ($scope.userDomain = $scope.originalUserDomain, $scope.originalUserDomain = angular.copy($scope.userDomain), 
            $scope.setSuccessAlert("Tool scope reset successfully!"));
        });
    }, $scope.saveAndPublishDomain = function() {
        if ($scope.canPublish($scope.userDomain)) {
            var modalInstance = $modal.open({
                templateUrl: "views/domains/confirm-publish.html",
                controller: "ConfirmDialogCtrl",
                size: "md",
                backdrop: "static",
                keyboard: !1
            });
            modalInstance.result.then(function(result) {
                result && ($scope.loadingAction = !0, DomainsManager.saveAndPublish($scope.userDomain).then(function(result) {
                    $scope.userDomain = result, $scope.originalUserDomain = angular.copy(result), $scope.loadingAction = !1, 
                    $scope.setSuccessAlert("Tool scope " + $scope.userDomain.name + " is now public. Please note only public test plans will be visible to users!"), 
                    $scope.userDomain.domain === $rootScope.domain.domain && ($rootScope.domain = angular.copy(result), 
                    $rootScope.reloadPage());
                }, function(error) {
                    $scope.loadingAction = !1, $scope.setErrorAlert(error.text);
                }));
            });
        }
    }, $scope.publishDomain = function(dom) {
        if ($scope.canPublish(dom)) {
            var modalInstance = $modal.open({
                templateUrl: "views/domains/confirm-publish.html",
                controller: "ConfirmDialogCtrl",
                size: "md",
                backdrop: "static",
                keyboard: !1
            });
            modalInstance.result.then(function(result) {
                result && DomainsManager.publish(dom.id).then(function(result) {
                    $scope.setSuccessAlert("Tool scope " + dom.name + " is now public. Please note only public test plans will be visible to users!"), 
                    dom.domain === $rootScope.domain.domain && ($rootScope.domain = angular.copy(result), 
                    $rootScope.reloadPage());
                }, function(error) {
                    $scope.setErrorAlert(error.text);
                });
            });
        }
    }, $scope.hasWriteAccess = function(dom) {
        return userInfoService.isAuthenticated() && (userInfoService.isAdmin() || null != dom && dom.owner === userInfoService.getUsername());
    }, $scope.canPublish = function(dom) {
        return $scope.hasWriteAccess(dom) && (userInfoService.isAdmin() || userInfoService.isPublisher());
    }, $scope.unpublishDomain = function(dom) {
        if ($scope.canPublish(dom)) {
            var modalInstance = $modal.open({
                templateUrl: "views/domains/confirm-unpublish.html",
                controller: "ConfirmDialogCtrl",
                size: "md",
                backdrop: "static",
                keyboard: !1
            });
            modalInstance.result.then(function(result) {
                result && DomainsManager.unpublish(dom.id).then(function(result) {
                    $scope.setSuccessAlert("Tool scope " + dom.name + " is now private!"), dom.domain === $rootScope.domain.domain && ($rootScope.domain = angular.copy(result), 
                    $rootScope.reloadPage());
                }, function(error) {
                    $scope.setErrorAlert(error.text);
                });
            });
        }
    }, $scope.saveAndUnpublishDomain = function() {
        if ($scope.canPublish($scope.userDomain)) {
            var modalInstance = $modal.open({
                templateUrl: "views/domains/confirm-unpublish.html",
                controller: "ConfirmDialogCtrl",
                size: "md",
                backdrop: "static",
                keyboard: !1
            });
            modalInstance.result.then(function(result) {
                result && ($scope.loadingAction = !0, DomainsManager.saveAndUnpublish($scope.userDomain).then(function(result) {
                    $scope.userDomain = result, $scope.originalUserDomain = angular.copy(result), $scope.loadingAction = !1, 
                    $scope.setSuccessAlert("Tool scope " + $scope.userDomain.name + " is now private. Please note only you can access the tool scope!"), 
                    $scope.userDomain.domain === $rootScope.domain.domain && ($rootScope.domain = angular.copy(result), 
                    $rootScope.reloadPage());
                }, function(error) {
                    $scope.loadingAction = !1, $scope.setErrorAlert(error.text);
                }));
            });
        }
    }, $scope.loadDefaultHomeContent = function() {
        DomainsManager.getDefaultHomeContent().then(function(result) {
            $scope.userDomain.homeContent = result;
        }, function(error) {
            $scope.loadingAction = !1, $scope.setErrorAlert(error);
        });
    }, $scope.loadDefaultProfileInfo = function() {
        DomainsManager.getDefaultProfileInfo().then(function(result) {
            $scope.userDomain.profileInfo = result;
        }, function(error) {
            $scope.setErrorAlert(error);
        });
    }, $scope.loadDefaultValueSetCopyright = function() {
        DomainsManager.getDefaultValueSetCopyright().then(function(result) {
            $scope.userDomain.valueSetCopyright = result;
        }, function(error) {
            $scope.setErrorAlert(error);
        });
    }, $scope.loadDefaultMessageContent = function() {
        DomainsManager.getDefaultMessageContent().then(function(result) {
            $scope.userDomain.messageContent = result;
        }, function(error) {
            $scope.setErrorAlert(error);
        });
    }, $scope.loadDefaultValidationResultInfo = function() {
        DomainsManager.getDefaultValidationResultInfo().then(function(result) {
            $scope.userDomain.validationResultInfo = result;
        }, function(error) {
            $scope.setErrorAlert(error);
        });
    };
}), angular.module("domains").controller("CreateDomainCtrl", function($scope, $modalInstance, scope, DomainsManager) {
    $scope.newDomain = {
        name: null,
        domain: null,
        homeTitle: null
    }, $scope.error = null, $scope.loading = !1, $scope.submit = function() {
        null != $scope.newDomain.name && "" != $scope.newDomain.name && null != $scope.newDomain.homeTitle && "" != $scope.newDomain.homeTitle && "app" != $scope.newDomain.name.toLowerCase() && ($scope.error = null, 
        $scope.loading = !0, $scope.newDomain.domain = $scope.newDomain.name.replace(/\s+/g, "-").toLowerCase(), 
        DomainsManager.create($scope.newDomain.name, $scope.newDomain.domain, scope, $scope.newDomain.homeTitle).then(function(result) {
            $scope.loading = !1, $modalInstance.close(result);
        }, function(error) {
            $scope.loading = !1, $scope.error = error.text;
        }));
    }, $scope.cancel = function() {
        $modalInstance.dismiss("cancel");
    };
}), angular.module("logs").directive("stLogDateRange", [ "$timeout", function($timeout) {
    return {
        restrict: "E",
        require: "^stTable",
        scope: {
            before: "=",
            after: "="
        },
        templateUrl: "stLogDateRange.html",
        link: function(scope, element, attr, table) {
            function open(before) {
                return function($event) {
                    $event.preventDefault(), $event.stopPropagation(), before ? scope.isBeforeOpen = !0 : scope.isAfterOpen = !0;
                };
            }
            var inputs = element.find("input"), inputBefore = angular.element(inputs[0]), inputAfter = angular.element(inputs[1]), predicateName = attr.predicate;
            [ inputBefore, inputAfter ].forEach(function(input) {
                input.bind("blur", function() {
                    var query = {};
                    scope.isBeforeOpen || scope.isAfterOpen || (scope.before && (query.before = scope.before), 
                    scope.after && (query.after = scope.after), scope.$apply(function() {
                        table.search(query, predicateName);
                    }));
                });
            }), scope.openBefore = open(!0), scope.openAfter = open();
        }
    };
} ]).directive("stNumberRange", [ "$timeout", function($timeout) {
    return {
        restrict: "E",
        require: "^stTable",
        scope: {
            lower: "=",
            higher: "="
        },
        templateUrl: "stNumberRange.html",
        link: function(scope, element, attr, table) {
            var inputs = element.find("input"), inputLower = angular.element(inputs[0]), inputHigher = angular.element(inputs[1]), predicateName = attr.predicate;
            [ inputLower, inputHigher ].forEach(function(input, index) {
                input.bind("blur", function() {
                    var query = {};
                    scope.lower && (query.lower = scope.lower), scope.higher && (query.higher = scope.higher), 
                    scope.$apply(function() {
                        table.search(query, predicateName);
                    });
                });
            });
        }
    };
} ]).filter("logCustomFilter", [ "$filter", function($filter) {
    var filterFilter = $filter("filter"), standardComparator = function(obj, text) {
        return text = ("" + text).toLowerCase(), ("" + obj).toLowerCase().indexOf(text) > -1;
    };
    return function(array, expression) {
        function customComparator(actual, expected) {
            var higherLimit, lowerLimit, itemDate, queryDate, isBeforeActivated = expected.before, isAfterActivated = expected.after, isLower = expected.lower, isHigher = expected.higher;
            if (angular.isObject(expected)) {
                if (expected.before || expected.after) try {
                    return !(isBeforeActivated && (higherLimit = expected.before, itemDate = new Date(actual), 
                    queryDate = new Date(higherLimit), queryDate.setDate(queryDate.getDate() + 1), itemDate > queryDate)) && !(isAfterActivated && (lowerLimit = expected.after, 
                    itemDate = new Date(actual), queryDate = new Date(lowerLimit), itemDate < queryDate));
                } catch (e) {
                    return !1;
                } else if (isLower || isHigher) return !(isLower && (higherLimit = expected.lower, 
                actual > higherLimit)) && !(isHigher && (lowerLimit = expected.higher, actual < lowerLimit));
                return !0;
            }
            return standardComparator(actual, expected);
        }
        var output = filterFilter(array, expression, customComparator);
        return output;
    };
} ]), angular.module("reports").controller("ReportsCtrl", [ "$scope", "ValidationLogService", "ReportService", "Notification", "$modal", "$rootScope", "$timeout", function($scope, ValidationLogService, ReportService, Notification, $modal, $rootScope, $timeout) {
    $scope.reports = null, $scope.tmpReports = null, $scope.logDetails = null, $scope.error = null, 
    $scope.loadingAll = !1, $scope.loadingOne = !1, $scope.allReports = [], $scope.tmpReports - [], 
    $scope.contextType = "*", $scope.userType = "*", $scope.resultType = "*", $scope.expandTCs = !0, 
    $scope.expandTree = !0, $scope.initReportsLogs = function() {
        $scope.loadingAll = !0, $timeout(function() {
            ReportService.getAllReportsByAccountIdAndDomain($rootScope.domain.domain).then(function(reports) {
                $scope.allReports = reports, $scope.contextType = "*", $scope.resultType = "*", 
                $scope.filterBy(), $scope.loadingAll = !1;
            }, function(error) {
                $scope.loadingAll = !1, $scope.error = "Sorry, Cannot load the reports. Please try again. \n DEBUG:" + error;
            });
        }, 1e3);
    }, $scope.toggleExpand = function() {
        for (var i = 0, len = $scope.reports.length; i < len; i++) $scope.reports[i].expanded = $scope.expandTCs;
    }, $scope.openReportDetails = function(report) {
        $modal.open({
            templateUrl: "ReportDetails.html",
            controller: "ReportDetailsCtrl",
            windowClass: "valueset-modal",
            animation: !1,
            keyboard: !0,
            backdrop: !0,
            resolve: {
                report: function() {
                    return report;
                }
            }
        });
    }, $scope.filterBy = function() {
        $scope.reports = $scope.filterByResultType($scope.filterByContextType($scope.allReports)), 
        $scope.tmpReports = [].concat($scope.reports);
    }, $scope.filterByContextType = function(inputLogs) {
        return _.filter(inputLogs, function(report) {
            return "*" === $scope.contextType || $scope.contextType === report.stage;
        });
    }, $scope.filterByResultType = function(inputLogs) {
        return _.filter(inputLogs, function(report) {
            return "*" === $scope.resultType || "SUCCESS" === $scope.resultType && ("PASSED" === report.result || "PASSED_NOTABLE_EXCEPTION" === report.result) || "FAILED" === $scope.resultType && ("FAILED" === report.result || "FAILED_NOT_SUPPORTED" === report.result);
        });
    }, $scope.deleteReport = function(report) {
        var modalInstance = $modal.open({
            templateUrl: "confirmReportDelete.html",
            controller: "ConfirmDialogCtrl",
            size: "md",
            backdrop: !0,
            keyboard: !0
        });
        modalInstance.result.then(function(resultDiag) {
            resultDiag && ("TESTSTEP" === report.type ? ReportService.deleteTSReport(report.id).then(function(result) {
                var index = $scope.reports.indexOf(report);
                index > -1 && $scope.reports.splice(index, 1), Notification.success({
                    message: "Report deleted successfully!",
                    templateUrl: "NotificationSuccessTemplate.html",
                    scope: $rootScope,
                    delay: 5e3
                });
            }, function(error) {
                Notification.error({
                    message: "Report deletion failed! <br>If error persists, please contact the website administrator.",
                    templateUrl: "NotificationErrorTemplate.html",
                    scope: $rootScope,
                    delay: 1e4
                });
            }) : "TESTCASE" === report.type && ReportService.deleteTCReport(report.id).then(function(result) {
                var index = $scope.reports.indexOf(report);
                index > -1 && $scope.reports.splice(index, 1), Notification.success({
                    message: "Report deleted successfully!",
                    templateUrl: "NotificationSuccessTemplate.html",
                    scope: $rootScope,
                    delay: 5e3
                });
            }, function(error) {
                Notification.error({
                    message: "Report deletion failed! <br>If error persists, please contact the website administrator.",
                    templateUrl: "NotificationErrorTemplate.html",
                    scope: $rootScope,
                    delay: 1e4
                });
            }));
        }, function(resultDiag) {});
    };
} ]), angular.module("reports").controller("ReportDetailsCtrl", function($scope, $modalInstance, report, ReportService) {
    $scope.report = report, $scope.type = $scope.report.type, $scope.loading = !0, "TESTSTEP" === $scope.report.type && ReportService.getUserTSReportHTML($scope.report.id).then(function(fullReport) {
        $scope.reportItem = fullReport;
    }, function(error) {
        Notification.error({
            message: "Report could not be loaded! <br>If error persists, please contact the website administrator.",
            templateUrl: "NotificationErrorTemplate.html",
            scope: $rootScope,
            delay: 1e4
        });
    }).finally(function() {
        $scope.loading = !1;
    }), "TESTCASE" === $scope.report.type && ReportService.getUserTCReportHTML($scope.report.id).then(function(fullReport) {
        $scope.reportItem = fullReport;
    }, function(error) {
        Notification.error({
            message: "Report could not be loaded! <br>If error persists, please contact the website administrator.",
            templateUrl: "NotificationErrorTemplate.html",
            scope: $rootScope,
            delay: 1e4
        });
    }).finally(function() {
        $scope.loading = !1;
    }), $scope.close = function() {
        $modalInstance.dismiss("cancel");
    }, $scope.downloadAs = function(format) {
        if ($scope.report) {
            if ("TESTSTEP" === $scope.report.type) return ReportService.downloadUserTestStepValidationReport($scope.report.id, format);
            if ("TESTCASE" === $scope.report.type) return ReportService.downloadUserTestCaseValidationReport($scope.report.id, format);
        }
    };
}), angular.module("hit-settings").controller("SettingsCtrl", [ "$scope", "$modalInstance", "StorageService", "$rootScope", "SettingsService", "userInfoService", "Notification", function($scope, $modalInstance, StorageService, $rootScope, SettingsService, userInfoService, Notification) {
    $scope.options = angular.copy(SettingsService.options), SettingsService.getValidationClassifications($rootScope.domain).then(function(classifications) {
        $scope.domainClassifications = classifications;
    }), $scope.onCheckAllValidationOptions = function($event) {
        var checkbox = $event.target;
        checkbox.checked ? $scope.selectAllValidationOptions() : $scope.unselectAllValidationOptions();
    }, $scope.selectAllValidationOptions = function() {
        $scope.options.validation.show.errors = !0, $scope.options.validation.show.alerts = !0, 
        $scope.options.validation.show.warnings = !0, $scope.options.validation.show.affirmatives = !0, 
        $scope.options.validation.show.informationals = !0, $scope.options.validation.show.specerrors = !0;
    }, $scope.isAllValidationOptionsChecked = function() {}, $scope.unselectAllValidationOptions = function() {
        $scope.options.validation.show.errors = !0, $scope.options.validation.show.alerts = !1, 
        $scope.options.validation.show.warnings = !1, $scope.options.validation.show.affirmatives = !1, 
        $scope.options.validation.show.informationals = !1, $scope.options.validation.show.specerrors = !1;
    }, $scope.cancel = function() {
        $modalInstance.dismiss("cancel");
    }, $scope.isAdmin = function() {
        return userInfoService.isAdmin();
    }, $rootScope.isDomainOwner = function() {
        return null != $rootScope.domain && $rootScope.domain.owner === userInfoService.getUsername();
    }, $scope.save = function() {
        SettingsService.set($scope.options), ($scope.isAdmin() || $rootScope.isDomainOwner()) && SettingsService.saveValidationClassifications($scope.domainClassifications, $rootScope.domain).then(function(result) {
            Notification.success({
                message: "Validation parameters save successfully!",
                templateUrl: "NotificationSuccessTemplate.html",
                scope: $rootScope,
                delay: 3e3
            });
        }, function(error) {}), $modalInstance.close($scope.options);
    }, $scope.resetClassifications = function() {
        SettingsService.resetClassifications().then(function(classifications) {
            $scope.domainClassifications = classifications;
        });
    };
} ]);