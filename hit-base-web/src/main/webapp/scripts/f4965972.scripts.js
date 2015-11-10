"use strict";angular.module("commonServices",[]),angular.module("hit-util",[]),angular.module("common",["ngResource","my.resource","default","xml","hl7v2-edi","hl7v2","edi","hit-util"]),angular.module("cf",["common"]),angular.module("doc",["common"]),angular.module("cb",["common"]),angular.module("hit-tool-directives",[]),angular.module("hit-tool-services",["common"]);var app=angular.module("hit-tool",["ngRoute","ui.bootstrap","ngCookies","LocalStorageModule","ngResource","ngSanitize","ngAnimate","ui.bootstrap","angularBootstrapNavTree","QuickList","hit-util","format","default","hl7v2-edi","xml","hl7v2","edi","cf","cb","ngTreetable","blueimp.fileupload","hit-tool-directives","hit-tool-services","commonServices","smart-table","hit-profile-viewer","hit-validation-result","hit-vocab-search","hit-report-viewer","hit-testcase-viewer","hit-testcase-tree","hit-doc","hit-settings","doc"]);app.config(["$routeProvider","$httpProvider","localStorageServiceProvider",function(a,b,c){c.setPrefix("hit-tool").setStorageType("sessionStorage"),a.when("/",{templateUrl:"views/home.html"}).when("/home",{templateUrl:"views/home.html"}).when("/testing",{templateUrl:"../views/templates.html"}).when("/doc",{templateUrl:"views/doc.html"}).when("/setting",{templateUrl:"views/setting.html"}).when("/about",{templateUrl:"views/about.html"}).when("/contact",{templateUrl:"views/contact.html"}).when("/cf",{templateUrl:"views/cf/testing.html"}).when("/cb",{templateUrl:"views/cb/testing.html"}).otherwise({redirectTo:"/"})}]),app.run(["$rootScope","$location","$modal","TestingSettings","AppInfo","StorageService","$route","$window","$sce",function(a,b,c,d,e,f,g,h,i){a.appInfo={},a.stackPosition=0,a.scrollbarWidth=null,(new e).then(function(b){a.appInfo=b}),a.$watch(function(){return b.path()},function(b,c){if(a.activePath===b){var d,e=h.history.state;d=!!(e&&e.position<=a.stackPosition),d?a.stackPosition--:a.stackPosition++}else g.current&&(h.history.replaceState({position:a.stackPosition},""),a.stackPosition++)}),a.isActive=function(b){return b===a.activePath},a.setActive=function(c){""===c||"/"===c?b.path("/home"):a.activePath=c},a.isSubActive=function(b){return b===a.subActivePath},a.setSubActive=function(b){a.subActivePath=b,f.set(f.ACTIVE_SUB_TAB_KEY,b)},a.showError=function(b){var d=c.open({templateUrl:"ErrorDlgDetails.html",controller:"ErrorDetailsCtrl",resolve:{error:function(){return b}}});d.result.then(function(b){a.error=b},function(){})},a.cutString=function(a){return a.length>20&&(a=a.substring(0,20)+"..."),a},a.tabs=new Array,a.selectTestingType=function(b){a.tabs[0]=!1,a.tabs[1]=!1,a.tabs[2]=!1,a.tabs[3]=!1,a.tabs[4]=!1,a.tabs[5]=!1,a.activeTab=b,a.tabs[a.activeTab]=!0,d.setActiveTab(a.activeTab)},a.downloadArtifact=function(a){var b=document.createElement("form");b.action="api/testartifact/download",b.method="POST",b.target="_target";var c=document.createElement("input");c.name="path",c.value=a,b.appendChild(c),b.style.display="none",document.body.appendChild(b),b.submit()},a.toHTML=function(a){return i.trustAsHtml(a)},a.compile=function(a){return $compile(a)},a.$on("$locationChangeSuccess",function(){a.setActive(b.path())}),a.getScrollbarWidth=function(){if(null==a.scrollbarWidth){var b=document.createElement("div");b.style.visibility="hidden",b.style.width="100px",b.style.msOverflowStyle="scrollbar",document.body.appendChild(b);var c=b.offsetWidth;b.style.overflow="scroll";var d=document.createElement("div");d.style.width="100%",b.appendChild(d);var e=d.offsetWidth;b.parentNode.removeChild(b),a.scrollbarWidth=c-e}return a.scrollbarWidth},a.openValidationResultInfo=function(){c.open({templateUrl:"ValidationResultInfoCtrl.html",windowClass:"profile-modal",controller:"ValidationResultInfoCtrl"})},a.showSettings=function(){c.open({templateUrl:"SettingsCtrl.html",size:"lg",keyboard:"false",controller:"SettingsCtrl"})}}]),angular.module("ui.bootstrap.carousel",["ui.bootstrap.transition"]).controller("CarouselController",["$scope","$timeout","$transition","$q",function(a,b,c,d){}]).directive("carousel",[function(){return{}}]),angular.module("hit-tool-services").factory("TabSettings",["$rootScope",function(a){return{"new":function(a){return{key:a,activeTab:0,getActiveTab:function(){return this.activeTab},setActiveTab:function(a){this.activeTab=a,this.save()},save:function(){sessionStorage.setItem(this.key,this.activeTab)},restore:function(){this.activeTab=null!=sessionStorage.getItem(this.key)&&""!=sessionStorage.getItem(this.key)?parseInt(sessionStorage.getItem(this.key)):0}}}}}]),app.controller("ErrorDetailsCtrl",["$scope","$modalInstance","error",function(a,b,c){a.error=c,a.ok=function(){b.close(a.error)},a.cancel=function(){b.dismiss("cancel")}}]),app.directive("stRatio",function(){return{link:function(a,b,c){var d=+c.stRatio;b.css("width",d+"%")}}}),angular.module("hit-tool-services").factory("AppInfo",["$http","$q",function(a,b){return function(){var c=b.defer();return a.get("api/appInfo").then(function(a){c.resolve(angular.fromJson(a.data))},function(a){c.reject(a.data)}),c.promise}}]),app.controller("TableFoundCtrl",["$scope","$modalInstance","table",function(a,b,c){a.table=c,a.tmpTableElements=[].concat(null!=c?c.valueSetElements:[]),a.cancel=function(){b.dismiss("cancel")}}]),app.controller("ValidationResultInfoCtrl",["$scope","$modalInstance",function(a,b){a.close=function(){b.dismiss("cancel")}}]),angular.module("my.resource",["ngResource"]).factory("Resource",["$resource",function(a){return function(b,c,d){var e={update:{method:"put",isArray:!1},create:{method:"post"}};d=angular.extend(e,d);var f=a(b,c,d);return f.prototype.$save=function(a,b){return this.id?this.$update(a,b):this.$create(a,b)},f}}]),angular.module("hit-tool-services").factory("TestingSettings",["$rootScope",function(a){var b={activeTab:0,getActiveTab:function(){return b.activeTab},setActiveTab:function(a){b.activeTab=a,b.save()},save:function(){sessionStorage.TestingActiveTab=b.activeTab},restore:function(){b.activeTab=null!=sessionStorage.TestingActiveTab&&""!=sessionStorage.TestingActiveTab?parseInt(sessionStorage.TestingActiveTab):0}};return b}]),angular.module("commonServices").factory("StorageService",["$rootScope","localStorageService",function(a,b){var c={CF_EDITOR_CONTENT_KEY:"CF_EDITOR_CONTENT",CF_LOADED_TESTCASE_ID_KEY:"CF_LOADED_TESTCASE_ID",CF_LOADED_TESTCASE_TYPE_KEY:"CF_LOADED_TESTCASE_TYPE",CB_EDITOR_CONTENT_KEY:"CB_EDITOR_CONTENT",CB_SELECTED_TESTCASE_ID_KEY:"CB_SELECTED_TESTCASE_ID",CB_SELECTED_TESTCASE_TYPE_KEY:"CB_SELECTED_TESTCASE_TYPE",CB_LOADED_TESTCASE_ID_KEY:"CB_LOADED_TESTCASE_ID",CB_LOADED_TESTCASE_TYPE_KEY:"CB_LOADED_TESTCASE_TYPE",CB_LOADED_TESTSTEP_TYPE_KEY:"CB_LOADED_TESTSTEP_TYPE_KEY",CB_LOADED_TESTSTEP_ID_KEY:"CB_LOADED_TESTSTEP_ID",SENDER_USERNAME_KEY:"SENDER_USERNAME",SENDER_PWD_KEY:"SENDER_PWD",SENDER_ENDPOINT_KEY:"SENDER_ENDPOINT",SENDER_FACILITYID_KEY:"SENDER_FACILITYID",RECEIVER_USERNAME_KEY:"RECEIVER_USERNAME",RECEIVER_PWD_KEY:"RECEIVER_PWD",RECEIVER_ENDPOINT_KEY:"RECEIVER_ENDPOINT",RECEIVER_FACILITYID_KEY:"RECEIVER_FACILITYID",ACTIVE_SUB_TAB_KEY:"ACTIVE_SUB_TAB",CB_TESTCASE_LOADED_RESULT_MAP_KEY:"CB_TESTCASE_LOADED_RESULT_MAP_KEY",SETTINGS_KEY:"SETTINGS_KEY",remove:function(a){return b.remove(a)},removeList:function(a,c,d){return b.remove(a,c,d)},clearAll:function(){return b.clearAll()},set:function(a,c){return b.set(a,c)},get:function(a){return b.get(a)}};return c}]),angular.module("cf").factory("CF",["Message","Tree",function(a,b){var c={editor:null,cursor:null,tree:new b,testCase:null,selectedTestCase:null,message:new a,searchTableId:0};return c}]),angular.module("cf").factory("CFTestCaseListLoader",["$q","$http",function(a,b){return function(){var c=a.defer();return b.get("api/cf/testcases",{timeout:6e4}).then(function(a){c.resolve(angular.fromJson(a.data))},function(a){c.reject(a.data)}),c.promise}}]),angular.module("cb").factory("CB",["Message","ValidationSettings","Tree","StorageService","CBCommunicationUser","Logger",function(a,b,c,d,e,f){var g=function(){var a=new e;return a.receiverUsername=d.get(d.RECEIVER_USERNAME_KEY),a.receiverPassword=d.get(d.RECEIVER_PWD_KEY),a.receiverFacilityId=d.get(d.RECEIVER_FACILITYID_KEY),a.receiverEndpoint=d.get(d.RECEIVER_ENDPOINT_KEY),a},h={testCase:null,selectedTestCase:null,editor:null,tree:new c,user:g(),cursor:null,message:new a,logger:new f,validationSettings:new b,setContent:function(a){h.message.content=a,h.editor.instance.doc.setValue(a),h.message.notifyChange()},getContent:function(){return h.message.content}};return h}]),angular.module("cb").factory("CBTestCaseListLoader",["$q","$http",function(a,b){return function(){var c=a.defer();return b.get("api/cb/testcases").then(function(a){c.resolve(angular.fromJson(a.data))},function(a){c.reject(a.data)}),c.promise}}]),angular.module("cb").factory("CBCommunicationUser",["Endpoint","CBTransaction","$q","$http",function(a,b,c,d){var e=function(){this.id=null,this.senderUsername=null,this.senderPassword=null,this.senderFacilityID=null,this.receiverUsername=null,this.receiverPassword=null,this.receiverFacilityId=null,this.receiverEndpoint=null,this.endpoint=new a,this.transaction=new b};return e.prototype.init=function(){var b=c.defer(),e=this,f=angular.fromJson({id:e.id});return d.post("api/transaction/initUser",f).then(function(c){var d=angular.fromJson(c.data);e.id=d.id,e.senderUsername=d.username,e.senderPassword=d.password,e.senderFacilityID=d.facilityID,e.endpoint=new a(d.endpoint),e.transaction.init(e.senderUsername,e.senderPassword,e.senderFacilityID),b.resolve(!0)},function(a){b.reject(a)}),b.promise},e}]),angular.module("cb").factory("CBInitiator",["$q","$http",function(a,b){var c=function(){};return c.prototype.send=function(c,d,e){var f=a.defer(),g=angular.fromJson({testCaseId:d,content:e,endpoint:c.receiverEndpoint,u:c.receiverUsername,p:c.receiverPassword,facilityId:c.receiverFacilityId});return b.post("api/isolated/soap/send",g,{timeout:6e4}).then(function(a){f.resolve(angular.fromJson(a.data))},function(a){f.reject(a)}),f.promise},c}]),angular.module("cb").factory("CBTransaction",["$q","$http",function(a,b){var c=function(){this.username=null,this.running=!1,this.password=null,this.facilityID=null,this.incoming=null,this.outgoing=null};return c.prototype.messages=function(){var c=a.defer(),d=this,e=angular.fromJson({username:d.username,password:d.password,facilityID:d.facilityID});return b.post("api/transaction",e).then(function(a){var b=angular.fromJson(a.data);d.incoming=b.incoming,d.outgoing=b.outgoing,c.resolve(b)},function(a){c.reject(null)}),c.promise},c.prototype.init=function(a,b,c){this.clearMessages(),this.username=a,this.password=b,this.facilityID=c},c.prototype.clearMessages=function(){this.incoming=null,this.outgoing=null},c.prototype.closeConnection=function(){var c=this,d=a.defer(),e=angular.fromJson({username:c.username,password:c.password,facilityID:c.facilityID});return b.post("api/transaction/close",e).then(function(a){c.running=!0,c.clearMessages(),d.resolve(!0)},function(a){c.running=!1,d.reject(null)}),d.promise},c.prototype.openConnection=function(c){var d=this,e=a.defer(),f=angular.fromJson({username:d.username,password:d.password,facilityID:d.facilityID,responseMessageId:c});return b.post("api/transaction/open",f).then(function(a){d.running=!0,d.clearMessages(),e.resolve(!0)},function(a){d.running=!1,e.reject(null)}),e.promise},c}]),angular.module("cb").factory("CBExecutionService",["$q","$http",function(a,b){var c=function(){};return c.setExecutionStatus=function(a,b){null!=a&&(a.executionStatus=b)},c.getExecutionStatus=function(a){return null!=a?a.executionStatus:void 0},c.getValidationStatus=function(a){return null!=a&&a.validationReport&&a.validationReport.result&&a.validationReport.result.errors&&a.validationReport.result.errors.categories[0]&&a.validationReport.result.errors.categories[0].data?a.validationReport.result.errors.categories[0].data.length:-1},c.getValidationResult=function(a){return null!=a&&a.validationReport?a.validationReport.result:void 0},c.setExecutionMessage=function(a,b){null!=a&&(a.executionMessage=b)},c.getExecutionMessage=function(a){return null!=a?a.executionMessage:void 0},c.setMessageTree=function(a,b){null!=a&&(a.messageTree=b)},c.getMessageTree=function(a){return null!=a?a.messageTree:void 0},c.getValidationReport=function(a){return null!=a?a.validationReport:void 0},c.setValidationReport=function(a,b){a.validationReport=b},c.deleteExecutionStatus=function(a){null!=a&&delete a.executionStatus},c.deleteValidationReport=function(a){a&&a.validationReport&&delete a.validationReport},c.deleteExecutionMessage=function(a){a&&a.executionMessage&&delete a.executionMessage},c.deleteMessageTree=function(a){a&&a.messageTree&&delete a.messageTree},c}]),angular.module("cb").factory("CBClock",["$interval","Clock",function(a,b){return new b(1e3)}]),angular.module("hit-tool").controller("ValidationResultDetailsCtrl",["$scope","$modalInstance","selectedElement",function(a,b,c){a.selectedElement=c,a.ok=function(){b.close(a.selectedElement)},a.cancel=function(){b.dismiss("cancel")}}]),angular.module("cf").controller("CFTestingCtrl",["$scope","$http","CF","$window","$modal","$filter","$rootScope","CFTestCaseListLoader","$timeout","StorageService","TestCaseService",function(a,b,c,d,e,f,g,h,i,j,k){a.cf=c,a.loading=!1,a.loadingTC=!1,a.error=null,a.testCases=[],a.testCase=null,a.tree={},a.tabs=new Array,a.error=null;var l=new k;a.setActiveTab=function(b){a.tabs[0]=!1,a.tabs[1]=!1,a.tabs[2]=!1,a.tabs[3]=!1,a.activeTab=b,a.tabs[a.activeTab]=!0},a.getTestCaseDisplayName=function(a){return a.parentName+" - "+a.label},a.selectTestCase=function(b){a.loadingTC=!0,i(function(){if(b.testContext&&null!=b.testContext){c.testCase=b,a.testCase=c.testCase;var d=j.get(j.CF_LOADED_TESTCASE_ID_KEY);d!=b.id&&(j.set(j.CF_LOADED_TESTCASE_ID_KEY,b.id),j.remove(j.CF_EDITOR_CONTENT_KEY)),a.$broadcast("cf:testCaseLoaded",a.testCase),a.$broadcast("cf:profileLoaded",a.testCase.testContext.profile),a.$broadcast("cf:valueSetLibraryLoaded",a.testCase.testContext.vocabularyLibrary)}a.loadingTC=!1})},a.init=function(){j.remove(j.ACTIVE_SUB_TAB_KEY),a.error=null,a.testCases=[],a.loading=!0;var b=new h;b.then(function(b){if(angular.forEach(b,function(a){l.buildCFTestCases(a)}),a.testCases=f("orderBy")(b,"position"),"function"==typeof a.tree.build_all){a.tree.build_all(a.testCases);var c=null,d=j.get(j.CF_LOADED_TESTCASE_ID_KEY);if(null!=d)for(var e=0;e<a.testCases.length;e++){var g=l.findOneById(d,a.testCases[e]);if(null!=g){c=g;break}}null!=c&&a.selectNode(c.id,c.type),a.error=null}else a.error="Something went wrong, Please refresh your page.";a.loading=!1},function(b){a.error="Something went wrong, Please refresh your page.",a.loading=!1})},a.selectNode=function(b,c){i(function(){l.selectNodeByIdAndType(a.tree,b,c)},0)},a.openProfileInfo=function(){e.open({templateUrl:"CFProfileInfoCtrl.html",windowClass:"profile-modal",controller:"CFProfileInfoCtrl"})},a.isSelectable=function(a){return a.testContext&&null!=a.testContext}}]),angular.module("cf").controller("CFProfileInfoCtrl",["$scope","$modalInstance",function(a,b){a.close=function(){b.dismiss("cancel")}}]),angular.module("cf").controller("CFValidatorCtrl",["$scope","$http","CF","$window","$timeout","$modal","NewValidationResult","$rootScope","ServiceDelegator","StorageService",function(a,b,c,d,e,f,g,h,i,j){a.validator=null,a.parser=null,a.editorService=null,a.treeService=null,a.cursorService=null,a.cf=c,a.testCase=c.testCase,a.message=c.message,a.selectedMessage={},a.loading=!0,a.error=null,a.vError=null,a.vLoading=!0,a.mError=null,a.mLoading=!0,a.delimeters=[],a.counter=0,a.type="cf",a.loadRate=4e3,a.tokenPromise=null,a.editorInit=!1,a.nodelay=!1,a.resized=!1,a.selectedItem=null,a.activeTab=0,a.tError=null,a.tLoading=!1,a.dqaCodes=null!=j.get(j.DQA_OPTIONS_KEY)?angular.fromJson(j.get(j.DQA_OPTIONS_KEY)):[],a.showDQAOptions=function(){var b=f.open({templateUrl:"DQAConfig.html",controller:"DQAConfigCtrl",windowClass:"dq-modal",animation:!0,keyboard:!1,backdrop:!1});b.result.then(function(b){a.dqaCodes=b},function(){})},a.hasContent=function(){return""!=a.cf.message.content&&null!=a.cf.message.content},a.refreshEditor=function(){e(function(){a.editor&&a.editor.refresh()},1e3)},a.options={paramName:"file",formAcceptCharset:"utf-8",autoUpload:!0,type:"POST"},a.$on("fileuploadadd",function(b,c){(c.autoUpload||c.autoUpload!==!1&&$(this).fileupload("option","autoUpload"))&&c.process().done(function(){var b=c.files[0].name;c.url="api/message/upload";c.submit().success(function(c,d,e){a.nodelay=!0;var f=angular.fromJson(c);a.cf.message.name=b,a.cf.editor.instance.doc.setValue(f.content),a.mError=null,a.execute()}).error(function(c,d,e){a.cf.message.name=b,a.mError="Something went wrong, Cannot upload file: "+b+", Error: "+e}).complete(function(a,b,c){})})}),a.loadMessage=function(){a.cf.testCase.testContext.message&&null!=a.cf.testCase.testContext.message&&(a.nodelay=!0,a.selectedMessage=a.cf.testCase.testContext.message,null!=a.selectedMessage&&null!=a.selectedMessage.content?a.editor.doc.setValue(a.selectedMessage.content):(a.editor.doc.setValue(""),a.cf.message.id=null,a.cf.message.name=""),a.execute())},a.setLoadRate=function(b){a.loadRate=b},a.initCodemirror=function(){a.editor=CodeMirror.fromTextArea(document.getElementById("cfTextArea"),{lineNumbers:!0,fixedGutter:!0,theme:"elegant",readOnly:!1,showCursorWhenSelecting:!0,gutters:["CodeMirror-linenumbers","cm-edi-segment-name"]}),a.editor.setSize("100%",345),a.editor.on("keyup",function(){e(function(){var b=a.editor.doc.getValue();a.error=null,a.tokenPromise&&(e.cancel(a.tokenPromise),a.tokenPromise=void 0),c.message.name=null,""!==b.trim()?a.tokenPromise=e(function(){a.execute()},a.loadRate):a.execute()})}),a.editor.on("dblclick",function(b){e(function(){var b=a.cursorService.getCoordinate(a.editor,a.cf.tree);b.lineNumber=b.line,b.startIndex=b.startIndex+1,b.endIndex=b.endIndex+1,a.cf.cursor.init(b,!0),a.treeService.selectNodeByIndex(a.cf.tree.root,c.cursor,c.message.content)})})},a.validateMessage=function(){try{if(a.vLoading=!0,a.vError=null,null!=a.cf.testCase&&""!==a.cf.message.content){var b=a.cf.testCase.testContext.id,c=a.cf.message.content,d=(a.cf.testCase.label,a.validator.validate(b,c,null,"Free"));d.then(function(b){a.vLoading=!1,a.loadValidationResult(b)},function(b){a.vLoading=!1,a.vError=b,a.loadValidationResult(null)})}else a.loadValidationResult(null),a.vLoading=!1,a.vError=null}catch(e){a.vLoading=!1,a.vError=e,a.loadValidationResult(null)}},a.loadValidationResult=function(b){e(function(){a.$broadcast("cf:validationResultLoaded",b)})},a.select=function(b){if(void 0!=b&&null!=b.path&&-1!=b.line){var c=a.treeService.selectNodeByPath(a.cf.tree.root,b.line,b.path),d=null!=c?c.data:null;a.cf.cursor.init(null!=d?d.lineNumber:b.line,null!=d?d.startIndex-1:b.column-1,null!=d?d.endIndex-1:b.column-1,null!=d?d.startIndex-1:b.column-1,!1),a.editorService.select(a.editor,a.cf.cursor)}},a.clearMessage=function(){a.nodelay=!0,a.mError=null,a.editor&&(a.editor.doc.setValue(""),a.execute())},a.saveMessage=function(){a.cf.message.download()},a.parseMessage=function(){try{if(null!=a.cf.testCase&&null!=a.cf.testCase.testContext&&""!=a.cf.message.content){a.tLoading=!0;var b=a.parser.parse(a.cf.testCase.testContext.id,a.cf.message.content);b.then(function(b){a.tLoading=!1,a.cf.tree.root.build_all(b.elements),i.updateEditorMode(a.editor,b.delimeters,a.cf.testCase.testContext.format),a.editorService.setEditor(a.editor),a.treeService.setEditor(a.editor)},function(b){a.tLoading=!1,a.tError=b})}else"function"==typeof a.cf.tree.root.build_all&&a.cf.tree.root.build_all([]),a.tError=null,a.tLoading=!1}catch(c){a.tLoading=!1,a.tError=c}},a.onNodeSelect=function(b){a.treeService.getEndIndex(b,a.cf.message.content),a.cf.cursor.init(b.data,!1),a.editorService.select(a.editor,a.cf.cursor)},a.execute=function(){a.tokenPromise&&(e.cancel(a.tokenPromise),a.tokenPromise=void 0),null!=a.cf.testCase&&(a.error=null,a.tError=null,a.mError=null,a.vError=null,a.cf.message.content=a.editor.doc.getValue(),j.set(j.CF_EDITOR_CONTENT_KEY,a.cf.message.content),a.refreshEditor(),a.validateMessage(),a.parseMessage())},a.init=function(){a.vLoading=!1,a.tLoading=!1,a.mLoading=!1,a.error=null,a.tError=null,a.mError=null,a.vError=null,a.initCodemirror(),a.refreshEditor(),a.$on("cf:testCaseLoaded",function(b,c){if(a.testCase=c,null!=a.testCase){var d=null==j.get(j.CF_EDITOR_CONTENT_KEY)?"":j.get(j.CF_EDITOR_CONTENT_KEY);a.nodelay=!0,a.mError=null,a.cf.editor=i.getEditor(a.testCase.testContext.format),a.cf.editor.instance=a.editor,a.cf.cursor=i.getCursor(a.testCase.testContext.format),a.validator=i.getMessageValidator(a.testCase.testContext.format),a.parser=i.getMessageParser(a.testCase.testContext.format),a.editorService=i.getEditorService(a.testCase.testContext.format),a.treeService=i.getTreeService(a.testCase.testContext.format),a.cursorService=i.getCursorService(a.testCase.testContext.format),a.editor&&(a.editor.doc.setValue(d),a.execute())}})}}]),angular.module("cf").controller("CFReportCtrl",["$scope","$sce","$http","CF",function(a,b,c,d){a.cf=d}]),angular.module("cf").controller("CFVocabularyCtrl",["$scope","CF",function(a,b){a.cf=b}]),angular.module("cf").controller("CFProfileViewerCtrl",["$scope","CF","$rootScope",function(a,b,c){a.cf=b}]),angular.module("cb").controller("CBTestingCtrl",["$scope","$window","$rootScope","CB","StorageService","$timeout",function(a,b,c,d,e,f){a.init=function(){var a=e.get(e.ACTIVE_SUB_TAB_KEY);(null==a||"/cb_execution"!=a)&&(a="/cb_testcase"),c.setSubActive(a)},a.setSubActive=function(b){c.setSubActive(b),"/cb_execution"===b&&a.$broadcast("cb:refreshEditor")}}]),angular.module("cb").controller("CBExecutionCtrl",["$scope","$window","$rootScope","CB","$modal","CBInitiator","CBClock","Endpoint","CBExecutionService","$timeout","StorageService",function(a,b,c,d,e,f,g,h,i,j,k){a.loading=!1,a.error=null,a.tabs=new Array,a.testCase=null,a.testStep=null,a.logger=d.logger,a.connecting=!1,a.user=d.user,a.endpoint=null,a.hidePwd=!0,a.sent=null,a.received=null,a.configCollapsed=!0,a.counterMax=30,a.counter=0,a.listenerReady=!1,a.testStepListCollapsed=!1,a.warning=null;var l=["Incorrect message Received. Please check the log for more details","No Outbound message found","Invalid message Received. Please see console for more details.","Invalid message Sent. Please see console for more details."],m=function(a){return a},n=function(a){return a};a.setActiveTab=function(b){a.tabs[0]=!1,a.tabs[1]=!1,a.tabs[2]=!1,a.tabs[3]=!1,a.activeTab=b,a.tabs[a.activeTab]=!0},a.getTestType=function(){return d.testCase.type},a.disabled=function(){return null==d.testCase||null===d.testCase.id},a.getTestType=function(){return null!=a.testCase?a.testCase.type:""},a.initDataInstanceStep=function(b){var c=b.testContext;c&&null!=c&&(a.setActiveTab(0),j(function(){a.$broadcast("cb:testStepLoaded",b),a.$broadcast("cb:profileLoaded",c.profile),a.$broadcast("cb:valueSetLibraryLoaded",c.vocabularyLibrary)}))},a.resetTestCase=function(){k.remove(k.CB_LOADED_TESTSTEP_TYPE_KEY),k.remove(k.CB_LOADED_TESTSTEP_ID_KEY),a.execTestCase(a.testCase)},a.selectTestStep=function(b){d.testStep=b,a.testStep=b,k.set(k.CB_LOADED_TESTSTEP_TYPE_KEY,a.testStep.type),k.set(k.CB_LOADED_TESTSTEP_ID_KEY,a.testStep.id),null==b||a.isManualStep(b)||(void 0===b.executionMessage&&"TA_INITIATOR"===b.testingType&&i.setExecutionMessage(b,b.testContext.message.content),a.initDataInstanceStep(b))},a.clearTestStep=function(){d.testStep=null,a.testStep=null,a.$broadcast("isolated:removeTestStep")},a.getExecutionStatus=function(a){return i.getExecutionStatus(a)},a.getValidationStatus=function(a){return i.getValidationStatus(a)},a.isManualStep=function(a){return"TA_MANUAL"===a.testingType||"SUT_MANUAL"===a.testingType},a.isSutInitiator=function(a){return"SUT_INITIATOR"==a.testingType},a.isStepCompleted=function(b){return"COMPLETE"==a.getExecutionStatus(b)},a.completeStep=function(a){i.setExecutionStatus(a,"COMPLETE")},a.completeManualStep=function(b){a.completeStep(b)},a.progressStep=function(a){i.setExecutionStatus(a,"IN_PROGRESS")},a.executeNextTestStep=function(b){a.testStepListCollapsed=!1,a.isManualStep(b)&&a.completeStep(b),a.isLastStep(b)?a.completeTestCase():a.executeTestStep(a.findNextStep(b.position))},a.executeTestStep=function(b){a.warning=null,a.logger.clear(),null!=b&&(a.isManualStep(b)||(i.deleteValidationReport(b),a.isSutInitiator(b)&&i.setExecutionMessage(b,null)),a.selectTestStep(b))},a.completeTestCase=function(){a.testCase.executionStatus="COMPLETE",null!=d.editor.instance&&d.editor.instance.setOption("readOnly",!0),a.clearTestStep()},a.isTestCaseCompleted=function(){return a.testCase&&"COMPLETE"===a.testCase.executionStatus},a.isTestStepCompleted=function(b){return null!=b&&(!a.isManualStep(b)&&"COMPLETE"==a.getExecutionStatus(b)||a.isManualStep(b))},a.shouldNextStep=function(b){return null!=a.testStep&&a.testStep===b&&!a.isTestCaseCompleted()&&!a.isLastStep(b)&&a.isTestStepCompleted(b)},a.isLastStep=function(b){return null!=b&&null!=a.testCase&&a.testCase.children.length===b.position},a.isTestCaseSuccessful=function(){if(null!=a.testCase)for(var b=0;b<a.testCase.children.length;b++)if(a.getValidationStatus(a.testCase.children[b])>0)return!1;return!0},a.testStepSucceed=function(b){return a.getValidationStatus(b)<=0},a.findNextStep=function(b){for(var c=0;c<a.testCase.children.length;c++)if(a.testCase.children[c].position===b+1)return a.testCase.children[c];return null},a.clearExecution=function(){if(null!=a.testCase){for(var b=0;b<a.testCase.children.length;b++){var c=a.testCase.children[b];i.deleteExecutionStatus(c),i.deleteValidationReport(c),i.deleteExecutionMessage(c),i.deleteMessageTree(c)}delete a.testCase.executionStatus}},a.setNextStepMessage=function(b){var c=a.findNextStep(a.testStep.position);null==c||a.isManualStep(c)||(a.completeStep(c),i.setExecutionMessage(c,b))},a.log=function(b){a.logger.log(b)},a.isValidConfig=function(){return null!=a.user.receiverEndpoint&&""!=a.user.receiverEndpoint},a.outboundMessage=function(){return null!=a.testStep?a.testStep.testContext.message.content:null},a.isValidConfig=function(){return null!=a.user&&null!=a.user.receiverEndpoint&&""!=a.user.receiverEndpoint},a.hasRequestContent=function(){return null!=a.outboundMessage()&&""!=a.outboundMessage()},a.send=function(){if(a.configCollapsed=!1,a.connecting=!0,a.progressStep(a.testStep),a.error=null,""!=a.user.receiverEndpoint&&a.hasRequestContent()){a.logger.init(),a.received="",a.logger.logOutbound(0);var b=(new f).send(a.user,a.testStep.id,a.outboundMessage());b.then(function(b){var c=b.incoming,d=b.outgoing;a.logger.logOutbound(1),a.logger.log(d),a.logger.logOutbound(2),a.logger.log(c);try{a.completeStep(a.testStep);var e=n(c);a.logger.logOutbound(3),a.setNextStepMessage(e)}catch(f){a.error=l[0],a.logger.logOutbound(4),a.logger.logOutbound(3)}a.connecting=!1},function(b){a.connecting=!1,a.error=b.data,a.logger.log("Error: "+b.data),a.received="",a.completeStep(a.testStep),a.logger.logOutbound(5)})}else a.error=l[1],a.connecting=!1},a.stopListening=function(){a.connecting=!1,a.counter=a.counterMax,g.stop(),a.logger.logInbound(14),a.user.transaction.closeConnection().then(function(b){a.logger.logInbound(13)},function(a){})},a.startListening=function(){var b=a.findNextStep(a.testStep.position);if(null!=b){var c=b.testContext.message.id;a.configCollapsed=!1,a.logger.clear(),a.counter=0,a.connecting=!0,a.error=null,a.warning=null;var d="",e="";a.logger.logInbound(0),a.user.transaction.openConnection(c).then(function(b){a.logger.logInbound(1);var c=function(){++a.counter,a.logger.log(a.logger.getInbound(2)+a.counter+"s"),a.user.transaction.messages().then(function(b){var c=a.user.transaction.incoming,f=a.user.transaction.outgoing;if(a.counter<a.counterMax){if(null!=c&&""!=c&&""==d){a.logger.logInbound(3),a.log(c),d=c;try{var g=m(c);i.setExecutionMessage(a.testStep,g),j(function(){a.$broadcast("isolated:setEditorContent",g)})}catch(h){a.error=l[2],a.logger.logOutbound(4)}}if(null!=f&&""!=f&&""==e){a.logger.logInbound(12),a.log(f),e=f;try{var k=n(f);a.setNextStepMessage(k)}catch(h){a.error=l[3],a.logger.logOutbound(5),a.logger.logOutbound(6)}}""!=c&&""!=f&&null!=c&&null!=f&&a.stopListening()}else null==c||""==c?(a.warning=ConsoleService.getInboundLog(7),a.logger.logInbound(8)):(null==f||""==f)&&a.logger.logInbound(9),a.stopListening()},function(b){a.error=b,a.log("Error: "+b),a.received="",a.sent="",a.stopListening()})};g.start(c)},function(b){a.logger.log(a.logger.getInbound(10)+"Error: "+b),a.logger.logInbound(11),a.connecting=!1,a.error=b})}},a.downloadJurorDoc=function(a,b){var c=$("#"+a).html();if(c&&""!=c){var d=document.createElement("form");d.action="api/testartifact/generateJurorDoc/pdf",d.method="POST",d.target="_target";var e=document.createElement("textarea");e.name="html",e.value=c,d.appendChild(e);var f=document.createElement("input");f.name="type",f.value="JurorDocument",d.style.display="none",d.appendChild(f);var g=document.createElement("input");g.name="type",g.value=b,d.style.display="none",d.appendChild(g),document.body.appendChild(d),d.submit()}},a.downloadTestArtifact=function(b){if(null!=a.testCase){var c=document.createElement("form");c.action="api/testartifact/download",c.method="POST",c.target="_target";var d=document.createElement("input");d.name="path",d.value=b,c.appendChild(d),c.style.display="none",document.body.appendChild(c),c.submit()}},a.init=function(){a.$on("cb:testCaseLoaded",function(b,c,d){a.execTestCase(c,d)})},a.execTestCase=function(b,e){null!=b&&(a.loading=!0,d.testStep=null,a.testStep=null,a.setActiveTab(0),e=e&&null!=e?e:"/cb_execution",c.setSubActive(e),"/cb_execution"===e&&a.$broadcast("cb:refreshEditor"),j(function(){a.clearExecution(),a.logger.clear(),a.error=null,a.warning=null,a.connecting=!1,d.testCase=b,a.testCase=b,g.stop(),a.user.transaction.closeConnection().then(function(a){},function(a){}),a.user.init().then(function(b){a.endpoint=a.user.endpoint},function(a){}),a.testCase=b,"TestCase"===b.type?a.executeTestStep(a.testCase.children[0]):"TestStep"===b.type&&(a.setActiveTab(0),d.testStep=b,a.testStep=b,k.set(k.CB_LOADED_TESTSTEP_ID_KEY,a.testStep.id),("DATAINSTANCE"===b.testingType||"TA_RESPONDER"===b.testingType||"TA_INITIATOR"===b.testingType||"SUT_RESPONDER"===b.testingType||"SUT_INITIATOR"===b.testingType)&&a.initDataInstanceStep(b)),a.loading=!1}))}}]),angular.module("cb").controller("CBTestCaseCtrl",["$scope","$window","$filter","$rootScope","CB","$timeout","CBTestCaseListLoader","$sce","StorageService","TestCaseService",function(a,b,c,d,e,f,g,h,i,j){a.selectedTestCase=e.selectedTestCase,a.testCase=e.testCase,a.testCases=[],a.tree={},a.loading=!0,a.loadingTC=!1,a.error=null;var k=new j;a.init=function(){a.error=null,a.loading=!0;var b=new g;b.then(function(b){if(a.error=null,angular.forEach(b,function(a){k.buildTree(a)}),a.testCases=b,"function"==typeof a.tree.build_all){a.tree.build_all(a.testCases);var c=null,d=i.get(i.CB_SELECTED_TESTCASE_ID_KEY),e=i.get(i.CB_SELECTED_TESTCASE_TYPE_KEY);if(null!=d&&null!=e){for(var f=0;f<a.testCases.length;f++){var g=k.findOneByIdAndType(d,e,a.testCases[f]);if(null!=g){c=g;break}}null!=c&&a.selectNode(d,e)}if(c=null,d=i.get(i.CB_LOADED_TESTCASE_ID_KEY),e=i.get(i.CB_LOADED_TESTCASE_TYPE_KEY),null!=d&&null!=e){for(var f=0;f<a.testCases.length;f++){var g=k.findOneByIdAndType(d,e,a.testCases[f]);if(null!=g){c=g;break}}if(null!=c){var h=i.get(i.ACTIVE_SUB_TAB_KEY);a.loadTestCase(c,h,!1)}}}else a.error="Ooops, Something went wrong. Please refresh your page. We are sorry for the inconvenience.";a.loading=!1},function(b){a.loading=!1,a.error="Sorry, Cannot load the test cases. Please try again"})},a.isSelectable=function(a){return!0},a.selectTestCase=function(b){a.loadingTC=!0,a.selectedTestCase=b,i.set(i.CB_SELECTED_TESTCASE_ID_KEY,b.id),i.set(i.CB_SELECTED_TESTCASE_TYPE_KEY,b.type),f(function(){a.$broadcast("cb:testCaseSelected",a.selectedTestCase),a.loadingTC=!1;
})},a.selectNode=function(b,c){f(function(){k.selectNodeByIdAndType(a.tree,b,c)},0)},a.loadTestCase=function(a,b,c){i.get(i.CB_LOADED_TESTCASE_ID_KEY),i.get(i.CB_LOADED_TESTCASE_TYPE_KEY);i.set(i.CB_LOADED_TESTCASE_ID_KEY,a.id),i.set(i.CB_LOADED_TESTCASE_TYPE_KEY,a.type),(void 0===c||c===!0)&&i.remove(i.CB_EDITOR_CONTENT_KEY),d.$broadcast("cb:testCaseLoaded",a,b)}}]),angular.module("cb").controller("CBValidatorCtrl",["$scope","$http","CB","$window","$timeout","$modal","NewValidationResult","$rootScope","ServiceDelegator","StorageService","CBExecutionService",function(a,b,c,d,e,f,g,h,i,j,k){a.cb=c,a.testStep=null,a.message=c.message,a.loading=!0,a.error=null,a.vError=null,a.vLoading=!0,a.mError=null,a.mLoading=!0,a.counter=0,a.type="cb",a.loadRate=4e3,a.tokenPromise=null,a.editorInit=!1,a.nodelay=!1,a.resized=!1,a.selectedItem=null,a.activeTab=0,a.tError=null,a.tLoading=!1,a.isTestCase=function(){return null!=c.testCase&&"TestCase"===c.testCase.type},a.refreshEditor=function(){e(function(){a.editor&&a.editor.refresh()},1e3)},a.loadExampleMessage=function(){if(null!=a.testStep){var b=a.testStep.testContext;if(b){var c=b.message&&null!=b.message?b.message.content:"";a.isTestCase()&&k.setExecutionMessage(a.testStep,c),a.nodelay=!0,a.cb.editor.instance.doc.setValue(c),a.execute()}}},a.setLoadRate=function(b){a.loadRate=b},a.initCodemirror=function(){a.editor=CodeMirror.fromTextArea(document.getElementById("cb-textarea"),{lineNumbers:!0,fixedGutter:!0,theme:"elegant",readOnly:!1,showCursorWhenSelecting:!0}),a.editor.setSize("100%",345),a.editor.on("keyup",function(){e(function(){var b=a.editor.doc.getValue();a.error=null,a.tokenPromise&&(e.cancel(a.tokenPromise),a.tokenPromise=void 0),""!==b.trim()?a.tokenPromise=e(function(){a.execute()},a.loadRate):a.execute()})}),a.editor.on("dblclick",function(b){e(function(){var b=a.cursorService.getCoordinate(a.editor,a.cb.tree);b&&null!=b&&(b.lineNumber=b.line,b.startIndex=b.startIndex+1,b.endIndex=b.endIndex+1,a.cb.cursor.init(b,!0),a.treeService.selectNodeByIndex(a.cb.tree.root,c.cursor,c.message.content))})})},a.validateMessage=function(){try{if(null!=a.testStep)if(""!==a.cb.message.content&&null!=a.testStep.testContext){a.vLoading=!0,a.vError=null;var b=a.validator.validate(a.testStep.testContext.id,a.cb.message.content,a.testStep.nav,"Based",[],"1223");b.then(function(b){a.vLoading=!1,a.setValidationReport(b)},function(b){a.vLoading=!1,a.vError=b,a.setValidationReport(null)})}else a.setValidationReport(null),a.vLoading=!1,a.vError=null}catch(c){a.vLoading=!1,a.vError=null,a.setValidationReport(null)}},a.setValidationReport=function(b){null!=a.testStep&&(null!=b&&k.setExecutionStatus(a.testStep,"COMPLETE"),h.$broadcast("cb:validationResultLoaded",b))},a.setMessageTree=function(b){a.buildMessageTree(b);var c=b&&null!=b&&b.elements?b:void 0;k.setMessageTree(a.testStep,c)},a.buildMessageTree=function(b){if(null!=a.testStep){var c=b&&null!=b&&b.elements?b.elements:[];"function"==typeof a.cb.tree.root.build_all&&a.cb.tree.root.build_all(c);var d=b&&null!=b&&b.delimeters?b.delimeters:[];i.updateEditorMode(a.editor,d,a.testStep.testContext.format),a.editorService.setEditor(a.editor),a.treeService.setEditor(a.editor)}},a.clearMessage=function(){a.nodelay=!0,a.mError=null,null!=a.testStep&&(k.deleteValidationReport(a.testStep),k.deleteMessageTree(a.testStep)),a.editor&&(a.editor.doc.setValue(""),a.execute())},a.saveMessage=function(){a.cb.message.download()},a.parseMessage=function(){try{if(null!=a.testStep)if(""!=a.cb.message.content&&null!=a.testStep.testContext){a.tLoading=!0;var b=a.parser.parse(a.testStep.testContext.id,a.cb.message.content);b.then(function(b){a.tLoading=!1,a.setMessageTree(b)},function(b){a.tLoading=!1,a.tError=b,a.setMessageTree([])})}else a.setMessageTree([]),a.tError=null,a.tLoading=!1}catch(c){a.tLoading=!1,a.tError=c}},a.onNodeSelect=function(b){a.treeService.getEndIndex(b,a.cb.message.content),a.cb.cursor.init(b.data,!1),a.editorService.select(a.editor,a.cb.cursor)},a.execute=function(){a.tokenPromise&&(e.cancel(a.tokenPromise),a.tokenPromise=void 0),a.error=null,a.tError=null,a.mError=null,a.vError=null,a.cb.message.content=a.editor.doc.getValue(),j.set(j.CB_EDITOR_CONTENT_KEY,a.cb.message.content),a.refreshEditor(),a.isTestCase()&&a.isTestCaseCompleted()?(a.setValidationReport(k.getValidationReport(a.testStep)),a.setMessageTree(k.getMessageTree(a.testStep))):(k.setExecutionMessage(a.testStep,a.cb.message.content),k.deleteValidationReport(a.testStep),k.deleteMessageTree(a.testStep),a.validateMessage(),a.parseMessage())},a.clear=function(){a.vLoading=!1,a.tLoading=!1,a.mLoading=!1,a.error=null,a.tError=null,a.mError=null,a.vError=null,a.setValidationReport(null)},a.init=function(){a.clear(),a.initCodemirror(),a.$on("cb:refreshEditor",function(b){a.refreshEditor()}),a.$on("cb:clearEditor",function(b){a.clearMessage()}),h.$on("cb:reportLoaded",function(b,c){null!=a.testStep&&k.setValidationReport(a.testStep,c)}),a.$on("cb:testStepLoaded",function(b,c){if(a.clear(),a.testStep=c,null!=a.testStep.testContext){a.cb.editor=i.getEditor(a.testStep.testContext.format),a.cb.editor.instance=a.editor,a.cb.cursor=i.getCursor(a.testStep.testContext.format),a.validator=i.getMessageValidator(a.testStep.testContext.format),a.parser=i.getMessageParser(a.testStep.testContext.format),a.editorService=i.getEditorService(a.testStep.testContext.format),a.treeService=i.getTreeService(a.testStep.testContext.format),a.cursorService=i.getCursorService(a.testStep.testContext.format);var d=null;a.isTestCase()?(a.nodelay=!0,d=k.getExecutionMessage(a.testStep),d=d&&null!=d?d:""):(a.nodelay=!1,d=null==j.get(j.CB_EDITOR_CONTENT_KEY)?"":j.get(j.CB_EDITOR_CONTENT_KEY)),a.editor&&(a.editor.doc.setValue(d),a.execute())}}),a.$on("cb:removeTestStep",function(b,c){a.testStep=null}),a.$on("cb:setEditorContent",function(b,c){a.nodelay=!0;var d=null==c?"":c;a.editor.doc.setValue(d),a.cb.message.id=null,a.cb.message.name="",a.execute()})}}]),angular.module("cb").controller("CBProfileViewerCtrl",["$scope","CB",function(a,b){a.cb=b}]),angular.module("cb").controller("CBReportCtrl",["$scope","$sce","$http","CB",function(a,b,c,d){a.cb=d}]),angular.module("cb").controller("CBVocabularyCtrl",["$scope","CB",function(a,b){a.cb=b}]),angular.module("hit-tool").controller("ContactCtrl",["$scope","ContactLoader","ContactListLoader",function(a,b,c){a.init=function(){var b=new c;return b.then(function(b){a.contacts=b},function(b){a.error=b}),b}}]),angular.module("hit-tool").controller("AboutCtrl",["$scope","AppInfo",function(a,b){}]),angular.module("hit-tool-directives").directive("hl7editor",["$timeout",function(a){return{restrict:"A",link:function(a,b,c){a.editor=CodeMirror.fromTextArea(document.getElementById(c.id),{lineNumbers:!0,fixedGutter:!0,theme:"elegant",mode:"edi",readOnly:void 0!=c.readonly&&c.readonly,showCursorWhenSelecting:!0}),a.editor.setSize(null,300),a.editor.on("change",function(b){a.$emit(c.type+":editor:update")}),a.editor.on("dblclick",function(b){a.$emit(c.type+":editor:dblclick")}),a.editorInit=!0}}}]),angular.module("hit-tool-directives").directive("soapEditor",["$timeout",function(a){return{restrict:"A",link:function(a,b,c){a.editor=CodeMirror.fromTextArea(document.getElementById(c.id),{lineNumbers:!0,fixedGutter:!0,mode:"xml",readOnly:void 0!=c.readonly&&c.readonly,showCursorWhenSelecting:!0}),a.editor.setSize(null,300),a.editor.on("dblclick",function(b){a.$emit(c.type+":editor:dblclick")}),a.editorInit=!0}}}]),angular.module("hit-tool-directives").directive("mypopover",["$compile","$templateCache",function(a,b){return{restrict:"A",link:function(a,c,d){var e=b.get("profileInfo.html"),f={content:e,placement:"bottom",html:!0};$(c).popover(f)}}}]);