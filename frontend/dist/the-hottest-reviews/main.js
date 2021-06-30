(window["webpackJsonp"] = window["webpackJsonp"] || []).push([["main"],{

/***/ "./src/$$_lazy_route_resource lazy recursive":
/*!**********************************************************!*\
  !*** ./src/$$_lazy_route_resource lazy namespace object ***!
  \**********************************************************/
/*! no static exports found */
/***/ (function(module, exports) {

function webpackEmptyAsyncContext(req) {
	// Here Promise.resolve().then() is used instead of new Promise() to prevent
	// uncaught exception popping up in devtools
	return Promise.resolve().then(function() {
		var e = new Error("Cannot find module '" + req + "'");
		e.code = 'MODULE_NOT_FOUND';
		throw e;
	});
}
webpackEmptyAsyncContext.keys = function() { return []; };
webpackEmptyAsyncContext.resolve = webpackEmptyAsyncContext;
module.exports = webpackEmptyAsyncContext;
webpackEmptyAsyncContext.id = "./src/$$_lazy_route_resource lazy recursive";

/***/ }),

/***/ "./src/app/app-routing.module.ts":
/*!***************************************!*\
  !*** ./src/app/app-routing.module.ts ***!
  \***************************************/
/*! exports provided: AppRoutingModule */
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "AppRoutingModule", function() { return AppRoutingModule; });
/* harmony import */ var _angular_core__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @angular/core */ "./node_modules/@angular/core/fesm5/core.js");
/* harmony import */ var _angular_router__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @angular/router */ "./node_modules/@angular/router/fesm5/router.js");
/* harmony import */ var _sauce_list_sauce_list_component__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ./sauce-list/sauce-list.component */ "./src/app/sauce-list/sauce-list.component.ts");
/* harmony import */ var _sauce_form_sauce_form_component__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ./sauce-form/sauce-form.component */ "./src/app/sauce-form/sauce-form.component.ts");
/* harmony import */ var _single_sauce_single_sauce_component__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ./single-sauce/single-sauce.component */ "./src/app/single-sauce/single-sauce.component.ts");
/* harmony import */ var _auth_signup_signup_component__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! ./auth/signup/signup.component */ "./src/app/auth/signup/signup.component.ts");
/* harmony import */ var _auth_login_login_component__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(/*! ./auth/login/login.component */ "./src/app/auth/login/login.component.ts");
/* harmony import */ var _services_auth_guard_service__WEBPACK_IMPORTED_MODULE_7__ = __webpack_require__(/*! ./services/auth-guard.service */ "./src/app/services/auth-guard.service.ts");
var __decorate = (undefined && undefined.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};








var routes = [
    { path: 'signup', component: _auth_signup_signup_component__WEBPACK_IMPORTED_MODULE_5__["SignupComponent"] },
    { path: 'login', component: _auth_login_login_component__WEBPACK_IMPORTED_MODULE_6__["LoginComponent"] },
    { path: 'sauces', component: _sauce_list_sauce_list_component__WEBPACK_IMPORTED_MODULE_2__["SauceListComponent"], canActivate: [_services_auth_guard_service__WEBPACK_IMPORTED_MODULE_7__["AuthGuard"]] },
    { path: 'sauce/:id', component: _single_sauce_single_sauce_component__WEBPACK_IMPORTED_MODULE_4__["SingleSauceComponent"], canActivate: [_services_auth_guard_service__WEBPACK_IMPORTED_MODULE_7__["AuthGuard"]] },
    { path: 'new-sauce', component: _sauce_form_sauce_form_component__WEBPACK_IMPORTED_MODULE_3__["SauceFormComponent"], canActivate: [_services_auth_guard_service__WEBPACK_IMPORTED_MODULE_7__["AuthGuard"]] },
    { path: 'modify-sauce/:id', component: _sauce_form_sauce_form_component__WEBPACK_IMPORTED_MODULE_3__["SauceFormComponent"], canActivate: [_services_auth_guard_service__WEBPACK_IMPORTED_MODULE_7__["AuthGuard"]] },
    { path: '', pathMatch: 'full', redirectTo: 'sauces' },
    { path: '**', redirectTo: 'sauces' }
];
var AppRoutingModule = /** @class */ (function () {
    function AppRoutingModule() {
    }
    AppRoutingModule = __decorate([
        Object(_angular_core__WEBPACK_IMPORTED_MODULE_0__["NgModule"])({
            imports: [_angular_router__WEBPACK_IMPORTED_MODULE_1__["RouterModule"].forRoot(routes)],
            exports: [_angular_router__WEBPACK_IMPORTED_MODULE_1__["RouterModule"]],
            providers: [_services_auth_guard_service__WEBPACK_IMPORTED_MODULE_7__["AuthGuard"]]
        })
    ], AppRoutingModule);
    return AppRoutingModule;
}());



/***/ }),

/***/ "./src/app/app.component.html":
/*!************************************!*\
  !*** ./src/app/app.component.html ***!
  \************************************/
/*! no static exports found */
/***/ (function(module, exports) {

module.exports = "<app-header></app-header>\r\n<div class=\"container\">\r\n  <router-outlet></router-outlet>\r\n</div>\r\n"

/***/ }),

/***/ "./src/app/app.component.scss":
/*!************************************!*\
  !*** ./src/app/app.component.scss ***!
  \************************************/
/*! no static exports found */
/***/ (function(module, exports) {

module.exports = ".container {\n  position: relative;\n  width: 100%;\n  max-width: 1000px;\n  margin: auto; }\n\n/*# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbInNyYy9hcHAvQzpcXFVzZXJzXFx5dmVub1xcRGVza3RvcFxcUDZcXGZyb250ZW5kL3NyY1xcYXBwXFxhcHAuY29tcG9uZW50LnNjc3MiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6IkFBQUE7RUFDRSxtQkFBa0I7RUFDbEIsWUFBVztFQUNYLGtCQUFpQjtFQUNqQixhQUFZLEVBQ2IiLCJmaWxlIjoic3JjL2FwcC9hcHAuY29tcG9uZW50LnNjc3MiLCJzb3VyY2VzQ29udGVudCI6WyIuY29udGFpbmVyIHtcclxuICBwb3NpdGlvbjogcmVsYXRpdmU7XHJcbiAgd2lkdGg6IDEwMCU7XHJcbiAgbWF4LXdpZHRoOiAxMDAwcHg7XHJcbiAgbWFyZ2luOiBhdXRvO1xyXG59XHJcbiJdfQ== */"

/***/ }),

/***/ "./src/app/app.component.ts":
/*!**********************************!*\
  !*** ./src/app/app.component.ts ***!
  \**********************************/
/*! exports provided: AppComponent */
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "AppComponent", function() { return AppComponent; });
/* harmony import */ var _angular_core__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @angular/core */ "./node_modules/@angular/core/fesm5/core.js");
var __decorate = (undefined && undefined.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};

var AppComponent = /** @class */ (function () {
    function AppComponent() {
    }
    AppComponent = __decorate([
        Object(_angular_core__WEBPACK_IMPORTED_MODULE_0__["Component"])({
            selector: 'app-root',
            template: __webpack_require__(/*! ./app.component.html */ "./src/app/app.component.html"),
            styles: [__webpack_require__(/*! ./app.component.scss */ "./src/app/app.component.scss")]
        })
    ], AppComponent);
    return AppComponent;
}());



/***/ }),

/***/ "./src/app/app.module.ts":
/*!*******************************!*\
  !*** ./src/app/app.module.ts ***!
  \*******************************/
/*! exports provided: AppModule */
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "AppModule", function() { return AppModule; });
/* harmony import */ var _angular_platform_browser__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @angular/platform-browser */ "./node_modules/@angular/platform-browser/fesm5/platform-browser.js");
/* harmony import */ var _angular_core__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @angular/core */ "./node_modules/@angular/core/fesm5/core.js");
/* harmony import */ var _app_routing_module__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ./app-routing.module */ "./src/app/app-routing.module.ts");
/* harmony import */ var _app_component__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ./app.component */ "./src/app/app.component.ts");
/* harmony import */ var _auth_signup_signup_component__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ./auth/signup/signup.component */ "./src/app/auth/signup/signup.component.ts");
/* harmony import */ var _auth_login_login_component__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! ./auth/login/login.component */ "./src/app/auth/login/login.component.ts");
/* harmony import */ var _sauce_list_sauce_list_component__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(/*! ./sauce-list/sauce-list.component */ "./src/app/sauce-list/sauce-list.component.ts");
/* harmony import */ var _single_sauce_single_sauce_component__WEBPACK_IMPORTED_MODULE_7__ = __webpack_require__(/*! ./single-sauce/single-sauce.component */ "./src/app/single-sauce/single-sauce.component.ts");
/* harmony import */ var _sauce_form_sauce_form_component__WEBPACK_IMPORTED_MODULE_8__ = __webpack_require__(/*! ./sauce-form/sauce-form.component */ "./src/app/sauce-form/sauce-form.component.ts");
/* harmony import */ var _header_header_component__WEBPACK_IMPORTED_MODULE_9__ = __webpack_require__(/*! ./header/header.component */ "./src/app/header/header.component.ts");
/* harmony import */ var _angular_common_http__WEBPACK_IMPORTED_MODULE_10__ = __webpack_require__(/*! @angular/common/http */ "./node_modules/@angular/common/fesm5/http.js");
/* harmony import */ var _angular_forms__WEBPACK_IMPORTED_MODULE_11__ = __webpack_require__(/*! @angular/forms */ "./node_modules/@angular/forms/fesm5/forms.js");
/* harmony import */ var _angular_platform_browser_animations__WEBPACK_IMPORTED_MODULE_12__ = __webpack_require__(/*! @angular/platform-browser/animations */ "./node_modules/@angular/platform-browser/fesm5/animations.js");
/* harmony import */ var _angular_material__WEBPACK_IMPORTED_MODULE_13__ = __webpack_require__(/*! @angular/material */ "./node_modules/@angular/material/esm5/material.es5.js");
/* harmony import */ var _interceptors_auth_interceptor__WEBPACK_IMPORTED_MODULE_14__ = __webpack_require__(/*! ./interceptors/auth-interceptor */ "./src/app/interceptors/auth-interceptor.ts");
var __decorate = (undefined && undefined.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};















var AppModule = /** @class */ (function () {
    function AppModule() {
    }
    AppModule = __decorate([
        Object(_angular_core__WEBPACK_IMPORTED_MODULE_1__["NgModule"])({
            declarations: [
                _app_component__WEBPACK_IMPORTED_MODULE_3__["AppComponent"],
                _auth_signup_signup_component__WEBPACK_IMPORTED_MODULE_4__["SignupComponent"],
                _auth_login_login_component__WEBPACK_IMPORTED_MODULE_5__["LoginComponent"],
                _sauce_list_sauce_list_component__WEBPACK_IMPORTED_MODULE_6__["SauceListComponent"],
                _single_sauce_single_sauce_component__WEBPACK_IMPORTED_MODULE_7__["SingleSauceComponent"],
                _sauce_form_sauce_form_component__WEBPACK_IMPORTED_MODULE_8__["SauceFormComponent"],
                _header_header_component__WEBPACK_IMPORTED_MODULE_9__["HeaderComponent"]
            ],
            imports: [
                _angular_platform_browser__WEBPACK_IMPORTED_MODULE_0__["BrowserModule"],
                _app_routing_module__WEBPACK_IMPORTED_MODULE_2__["AppRoutingModule"],
                _angular_common_http__WEBPACK_IMPORTED_MODULE_10__["HttpClientModule"],
                _angular_forms__WEBPACK_IMPORTED_MODULE_11__["ReactiveFormsModule"],
                _angular_platform_browser_animations__WEBPACK_IMPORTED_MODULE_12__["BrowserAnimationsModule"],
                _angular_material__WEBPACK_IMPORTED_MODULE_13__["MatProgressSpinnerModule"],
                _angular_material__WEBPACK_IMPORTED_MODULE_13__["MatButtonModule"]
            ],
            providers: [{ provide: _angular_common_http__WEBPACK_IMPORTED_MODULE_10__["HTTP_INTERCEPTORS"], useClass: _interceptors_auth_interceptor__WEBPACK_IMPORTED_MODULE_14__["AuthInterceptor"], multi: true }],
            bootstrap: [_app_component__WEBPACK_IMPORTED_MODULE_3__["AppComponent"]]
        })
    ], AppModule);
    return AppModule;
}());



/***/ }),

/***/ "./src/app/auth/login/login.component.html":
/*!*************************************************!*\
  !*** ./src/app/auth/login/login.component.html ***!
  \*************************************************/
/*! no static exports found */
/***/ (function(module, exports) {

module.exports = "<mat-spinner *ngIf=\"loading\"></mat-spinner>\r\n<form [formGroup]=\"loginForm\" *ngIf=\"!loading\">\r\n  <div class=\"form-group\">\r\n    <label for=\"email\">Email</label>\r\n    <input type=\"email\" class=\"form-control\" id=\"email\" formControlName=\"email\">\r\n  </div>\r\n  <div class=\"form-group\">\r\n    <label for=\"password\">Password</label>\r\n    <input type=\"password\" class=\"form-control\" id=\"password\" formControlName=\"password\">\r\n  </div>\r\n  <button mat-raised-button color=\"primary\" [disabled]=\"loginForm.invalid\" (click)=\"onLogin()\">LOGIN</button>\r\n  <p class=\"text-danger\" *ngIf=\"errorMsg\">{{ errorMsg }}</p>\r\n</form>\r\n"

/***/ }),

/***/ "./src/app/auth/login/login.component.scss":
/*!*************************************************!*\
  !*** ./src/app/auth/login/login.component.scss ***!
  \*************************************************/
/*! no static exports found */
/***/ (function(module, exports) {

module.exports = "form {\n  margin: 2em auto;\n  max-width: 750px; }\n\n/*# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbInNyYy9hcHAvYXV0aC9sb2dpbi9DOlxcVXNlcnNcXHl2ZW5vXFxEZXNrdG9wXFxQNlxcZnJvbnRlbmQvc3JjXFxhcHBcXGF1dGhcXGxvZ2luXFxsb2dpbi5jb21wb25lbnQuc2NzcyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiQUFBQTtFQUNFLGlCQUFnQjtFQUNoQixpQkFBZ0IsRUFDakIiLCJmaWxlIjoic3JjL2FwcC9hdXRoL2xvZ2luL2xvZ2luLmNvbXBvbmVudC5zY3NzIiwic291cmNlc0NvbnRlbnQiOlsiZm9ybSB7XHJcbiAgbWFyZ2luOiAyZW0gYXV0bztcclxuICBtYXgtd2lkdGg6IDc1MHB4O1xyXG59XHJcbiJdfQ== */"

/***/ }),

/***/ "./src/app/auth/login/login.component.ts":
/*!***********************************************!*\
  !*** ./src/app/auth/login/login.component.ts ***!
  \***********************************************/
/*! exports provided: LoginComponent */
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "LoginComponent", function() { return LoginComponent; });
/* harmony import */ var _angular_core__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @angular/core */ "./node_modules/@angular/core/fesm5/core.js");
/* harmony import */ var _angular_forms__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @angular/forms */ "./node_modules/@angular/forms/fesm5/forms.js");
/* harmony import */ var _services_auth_service__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ../../services/auth.service */ "./src/app/services/auth.service.ts");
/* harmony import */ var _angular_router__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! @angular/router */ "./node_modules/@angular/router/fesm5/router.js");
var __decorate = (undefined && undefined.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (undefined && undefined.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};




var LoginComponent = /** @class */ (function () {
    function LoginComponent(formBuilder, auth, router) {
        this.formBuilder = formBuilder;
        this.auth = auth;
        this.router = router;
    }
    LoginComponent.prototype.ngOnInit = function () {
        this.loginForm = this.formBuilder.group({
            email: [null, [_angular_forms__WEBPACK_IMPORTED_MODULE_1__["Validators"].required, _angular_forms__WEBPACK_IMPORTED_MODULE_1__["Validators"].email]],
            password: [null, _angular_forms__WEBPACK_IMPORTED_MODULE_1__["Validators"].required]
        });
    };
    LoginComponent.prototype.onLogin = function () {
        var _this = this;
        this.loading = true;
        var email = this.loginForm.get('email').value;
        var password = this.loginForm.get('password').value;
        this.auth.loginUser(email, password).then(function () {
            _this.loading = false;
            _this.router.navigate(['/sauces']);
        }).catch(function (error) {
            _this.loading = false;
            _this.errorMsg = error.message;
        });
    };
    LoginComponent = __decorate([
        Object(_angular_core__WEBPACK_IMPORTED_MODULE_0__["Component"])({
            selector: 'app-login',
            template: __webpack_require__(/*! ./login.component.html */ "./src/app/auth/login/login.component.html"),
            styles: [__webpack_require__(/*! ./login.component.scss */ "./src/app/auth/login/login.component.scss")]
        }),
        __metadata("design:paramtypes", [_angular_forms__WEBPACK_IMPORTED_MODULE_1__["FormBuilder"],
            _services_auth_service__WEBPACK_IMPORTED_MODULE_2__["AuthService"],
            _angular_router__WEBPACK_IMPORTED_MODULE_3__["Router"]])
    ], LoginComponent);
    return LoginComponent;
}());



/***/ }),

/***/ "./src/app/auth/signup/signup.component.html":
/*!***************************************************!*\
  !*** ./src/app/auth/signup/signup.component.html ***!
  \***************************************************/
/*! no static exports found */
/***/ (function(module, exports) {

module.exports = "<mat-spinner *ngIf=\"loading\"></mat-spinner>\r\n<form [formGroup]=\"signupForm\" *ngIf=\"!loading\">\r\n  <div class=\"form-group\">\r\n    <label for=\"email\">Email</label>\r\n    <input type=\"email\" class=\"form-control\" id=\"email\" formControlName=\"email\">\r\n  </div>\r\n  <div class=\"form-group\">\r\n    <label for=\"password\">Password</label>\r\n    <input type=\"password\" class=\"form-control\" id=\"password\" formControlName=\"password\">\r\n  </div>\r\n  <button mat-raised-button color=\"primary\" [disabled]=\"signupForm.invalid\" (click)=\"onSignup()\">SIGN UP</button>\r\n  <p class=\"text-danger\" *ngIf=\"errorMsg\">{{ errorMsg }}</p>\r\n</form>\r\n"

/***/ }),

/***/ "./src/app/auth/signup/signup.component.scss":
/*!***************************************************!*\
  !*** ./src/app/auth/signup/signup.component.scss ***!
  \***************************************************/
/*! no static exports found */
/***/ (function(module, exports) {

module.exports = "form {\n  margin: 2em auto;\n  max-width: 750px; }\n\n/*# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbInNyYy9hcHAvYXV0aC9zaWdudXAvQzpcXFVzZXJzXFx5dmVub1xcRGVza3RvcFxcUDZcXGZyb250ZW5kL3NyY1xcYXBwXFxhdXRoXFxzaWdudXBcXHNpZ251cC5jb21wb25lbnQuc2NzcyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiQUFBQTtFQUNFLGlCQUFnQjtFQUNoQixpQkFBZ0IsRUFDakIiLCJmaWxlIjoic3JjL2FwcC9hdXRoL3NpZ251cC9zaWdudXAuY29tcG9uZW50LnNjc3MiLCJzb3VyY2VzQ29udGVudCI6WyJmb3JtIHtcclxuICBtYXJnaW46IDJlbSBhdXRvO1xyXG4gIG1heC13aWR0aDogNzUwcHg7XHJcbn1cclxuIl19 */"

/***/ }),

/***/ "./src/app/auth/signup/signup.component.ts":
/*!*************************************************!*\
  !*** ./src/app/auth/signup/signup.component.ts ***!
  \*************************************************/
/*! exports provided: SignupComponent */
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "SignupComponent", function() { return SignupComponent; });
/* harmony import */ var _angular_core__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @angular/core */ "./node_modules/@angular/core/fesm5/core.js");
/* harmony import */ var _angular_forms__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @angular/forms */ "./node_modules/@angular/forms/fesm5/forms.js");
/* harmony import */ var _services_auth_service__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ../../services/auth.service */ "./src/app/services/auth.service.ts");
/* harmony import */ var _angular_router__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! @angular/router */ "./node_modules/@angular/router/fesm5/router.js");
var __decorate = (undefined && undefined.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (undefined && undefined.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};




var SignupComponent = /** @class */ (function () {
    function SignupComponent(formBuilder, auth, router) {
        this.formBuilder = formBuilder;
        this.auth = auth;
        this.router = router;
    }
    SignupComponent.prototype.ngOnInit = function () {
        this.signupForm = this.formBuilder.group({
            email: [null, [_angular_forms__WEBPACK_IMPORTED_MODULE_1__["Validators"].required, _angular_forms__WEBPACK_IMPORTED_MODULE_1__["Validators"].email]],
            password: [null, _angular_forms__WEBPACK_IMPORTED_MODULE_1__["Validators"].required]
        });
    };
    SignupComponent.prototype.onSignup = function () {
        var _this = this;
        this.loading = true;
        var email = this.signupForm.get('email').value;
        var password = this.signupForm.get('password').value;
        this.auth.createUser(email, password).then(function (response) {
            console.log(response.message);
            _this.auth.loginUser(email, password).then(function () {
                _this.loading = false;
                _this.router.navigate(['/sauces']);
            }).catch(function (error) {
                _this.loading = false;
                console.error(error);
                _this.errorMsg = error.message;
            });
        }).catch(function (error) {
            _this.loading = false;
            console.error(error);
            _this.errorMsg = error.message;
        });
    };
    SignupComponent = __decorate([
        Object(_angular_core__WEBPACK_IMPORTED_MODULE_0__["Component"])({
            selector: 'app-signup',
            template: __webpack_require__(/*! ./signup.component.html */ "./src/app/auth/signup/signup.component.html"),
            styles: [__webpack_require__(/*! ./signup.component.scss */ "./src/app/auth/signup/signup.component.scss")]
        }),
        __metadata("design:paramtypes", [_angular_forms__WEBPACK_IMPORTED_MODULE_1__["FormBuilder"],
            _services_auth_service__WEBPACK_IMPORTED_MODULE_2__["AuthService"],
            _angular_router__WEBPACK_IMPORTED_MODULE_3__["Router"]])
    ], SignupComponent);
    return SignupComponent;
}());



/***/ }),

/***/ "./src/app/header/header.component.html":
/*!**********************************************!*\
  !*** ./src/app/header/header.component.html ***!
  \**********************************************/
/*! no static exports found */
/***/ (function(module, exports) {

module.exports = "<nav>\r\n  <div class=\"left-nav\">\r\n    <ul>\r\n      <li>\r\n        <a routerLink=\"sauces\" routerLinkActive=\"active\" *ngIf=\"isAuth\">\r\n          Toute les sauces\r\n        </a>\r\n      </li>\r\n      <li>\r\n        <a routerLink=\"new-sauce\" routerLinkActive=\"active\" *ngIf=\"isAuth\">\r\n          Ajouter une sauce\r\n        </a>\r\n      </li>\r\n    </ul>\r\n  </div>\r\n  <div class=\"logo\">\r\n    <div class=\"logo-image\">\r\n      <img src=\"../../assets/images/flame.png\">\r\n    </div>\r\n    <div class=\"logo-text\">\r\n      <h1>\r\n        Piquante\r\n      </h1>\r\n      <h5>\r\n        La meilleure application de notation de sauces\r\n      </h5>\r\n    </div>\r\n  </div>\r\n  <div class=\"right-nav\">\r\n    <ul>\r\n      <li>\r\n        <a routerLink=\"signup\" routerLinkActive=\"active\" *ngIf=\"!isAuth\">\r\n          Inscription\r\n        </a>\r\n      </li>\r\n      <li>\r\n        <a routerLink=\"login\" routerLinkActive=\"active\" *ngIf=\"!isAuth\">\r\n          Connexion\r\n        </a>\r\n      </li>\r\n      <li>\r\n        <a (click)=\"onLogout()\" *ngIf=\"isAuth\">\r\n          Déconnexion\r\n        </a>\r\n      </li>\r\n    </ul>\r\n  </div>\r\n</nav>\r\n"

/***/ }),

/***/ "./src/app/header/header.component.scss":
/*!**********************************************!*\
  !*** ./src/app/header/header.component.scss ***!
  \**********************************************/
/*! no static exports found */
/***/ (function(module, exports) {

module.exports = "nav {\n  box-sizing: border-box;\n  width: 100%;\n  max-width: 1400px;\n  margin: auto;\n  position: relative;\n  top: 0;\n  left: 0;\n  display: flex;\n  padding: 20px;\n  justify-content: space-between;\n  border-bottom: thin solid black; }\n\nh1 {\n  font-weight: 700;\n  font-size: 2.4em;\n  margin: 0; }\n\nh5 {\n  font-size: 1.2em;\n  font-weight: 400;\n  margin: 0; }\n\n.logo {\n  display: flex;\n  align-items: center; }\n\n.logo-text {\n  text-align: center; }\n\n.logo-image {\n  margin-right: 1em; }\n\n.logo-image img {\n    height: 4.5em; }\n\n.left-nav, .right-nav {\n  align-self: center;\n  width: 30%; }\n\n.right-nav ul {\n  justify-content: flex-end; }\n\nul {\n  list-style: none;\n  padding: 0;\n  margin: 0;\n  display: flex; }\n\nli {\n  margin: 0 15px; }\n\na {\n  color: black;\n  font-weight: 400;\n  text-decoration: none;\n  cursor: pointer; }\n\na:hover {\n    text-decoration: underline; }\n\n.active {\n  font-weight: 700;\n  text-decoration: underline; }\n\n/*# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbInNyYy9hcHAvaGVhZGVyL0M6XFxVc2Vyc1xceXZlbm9cXERlc2t0b3BcXFA2XFxmcm9udGVuZC9zcmNcXGFwcFxcaGVhZGVyXFxoZWFkZXIuY29tcG9uZW50LnNjc3MiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6IkFBQUE7RUFDRSx1QkFBc0I7RUFDdEIsWUFBVztFQUNYLGtCQUFpQjtFQUNqQixhQUFZO0VBQ1osbUJBQWtCO0VBQ2xCLE9BQU07RUFDTixRQUFPO0VBQ1AsY0FBYTtFQUNiLGNBQWE7RUFDYiwrQkFBOEI7RUFDOUIsZ0NBQStCLEVBQ2hDOztBQUVEO0VBQ0UsaUJBQWdCO0VBQ2hCLGlCQUFnQjtFQUNoQixVQUFTLEVBQ1Y7O0FBRUQ7RUFDRSxpQkFBZ0I7RUFDaEIsaUJBQWdCO0VBQ2hCLFVBQVMsRUFDVjs7QUFFRDtFQUNFLGNBQWE7RUFDYixvQkFBbUIsRUFDcEI7O0FBRUQ7RUFDRSxtQkFBa0IsRUFDbkI7O0FBRUQ7RUFJRSxrQkFBaUIsRUFDbEI7O0FBTEQ7SUFFSSxjQUFhLEVBQ2Q7O0FBSUg7RUFDRSxtQkFBa0I7RUFDbEIsV0FBVSxFQUNYOztBQUVEO0VBRUksMEJBQXlCLEVBQzFCOztBQUdIO0VBQ0UsaUJBQWdCO0VBQ2hCLFdBQVU7RUFDVixVQUFTO0VBQ1QsY0FBYSxFQUNkOztBQUVEO0VBQ0UsZUFBYyxFQUNmOztBQUVEO0VBQ0UsYUFBWTtFQUNaLGlCQUFnQjtFQUNoQixzQkFBcUI7RUFDckIsZ0JBQWUsRUFJaEI7O0FBUkQ7SUFNSSwyQkFBMEIsRUFDM0I7O0FBR0g7RUFDRSxpQkFBZ0I7RUFDaEIsMkJBQTBCLEVBQzNCIiwiZmlsZSI6InNyYy9hcHAvaGVhZGVyL2hlYWRlci5jb21wb25lbnQuc2NzcyIsInNvdXJjZXNDb250ZW50IjpbIm5hdiB7XHJcbiAgYm94LXNpemluZzogYm9yZGVyLWJveDtcclxuICB3aWR0aDogMTAwJTtcclxuICBtYXgtd2lkdGg6IDE0MDBweDtcclxuICBtYXJnaW46IGF1dG87XHJcbiAgcG9zaXRpb246IHJlbGF0aXZlO1xyXG4gIHRvcDogMDtcclxuICBsZWZ0OiAwO1xyXG4gIGRpc3BsYXk6IGZsZXg7XHJcbiAgcGFkZGluZzogMjBweDtcclxuICBqdXN0aWZ5LWNvbnRlbnQ6IHNwYWNlLWJldHdlZW47XHJcbiAgYm9yZGVyLWJvdHRvbTogdGhpbiBzb2xpZCBibGFjaztcclxufVxyXG5cclxuaDEge1xyXG4gIGZvbnQtd2VpZ2h0OiA3MDA7XHJcbiAgZm9udC1zaXplOiAyLjRlbTtcclxuICBtYXJnaW46IDA7XHJcbn1cclxuXHJcbmg1IHtcclxuICBmb250LXNpemU6IDEuMmVtO1xyXG4gIGZvbnQtd2VpZ2h0OiA0MDA7XHJcbiAgbWFyZ2luOiAwO1xyXG59XHJcblxyXG4ubG9nbyB7XHJcbiAgZGlzcGxheTogZmxleDtcclxuICBhbGlnbi1pdGVtczogY2VudGVyO1xyXG59XHJcblxyXG4ubG9nby10ZXh0IHtcclxuICB0ZXh0LWFsaWduOiBjZW50ZXI7XHJcbn1cclxuXHJcbi5sb2dvLWltYWdlIHtcclxuICBpbWcge1xyXG4gICAgaGVpZ2h0OiA0LjVlbTtcclxuICB9XHJcbiAgbWFyZ2luLXJpZ2h0OiAxZW07XHJcbn1cclxuXHJcbi5sZWZ0LW5hdiwgLnJpZ2h0LW5hdiB7XHJcbiAgYWxpZ24tc2VsZjogY2VudGVyO1xyXG4gIHdpZHRoOiAzMCU7XHJcbn1cclxuXHJcbi5yaWdodC1uYXYge1xyXG4gIHVsIHtcclxuICAgIGp1c3RpZnktY29udGVudDogZmxleC1lbmQ7XHJcbiAgfVxyXG59XHJcblxyXG51bCB7XHJcbiAgbGlzdC1zdHlsZTogbm9uZTtcclxuICBwYWRkaW5nOiAwO1xyXG4gIG1hcmdpbjogMDtcclxuICBkaXNwbGF5OiBmbGV4O1xyXG59XHJcblxyXG5saSB7XHJcbiAgbWFyZ2luOiAwIDE1cHg7XHJcbn1cclxuXHJcbmEge1xyXG4gIGNvbG9yOiBibGFjaztcclxuICBmb250LXdlaWdodDogNDAwO1xyXG4gIHRleHQtZGVjb3JhdGlvbjogbm9uZTtcclxuICBjdXJzb3I6IHBvaW50ZXI7XHJcbiAgJjpob3ZlciB7XHJcbiAgICB0ZXh0LWRlY29yYXRpb246IHVuZGVybGluZTtcclxuICB9XHJcbn1cclxuXHJcbi5hY3RpdmUge1xyXG4gIGZvbnQtd2VpZ2h0OiA3MDA7XHJcbiAgdGV4dC1kZWNvcmF0aW9uOiB1bmRlcmxpbmU7XHJcbn1cclxuIl19 */"

/***/ }),

/***/ "./src/app/header/header.component.ts":
/*!********************************************!*\
  !*** ./src/app/header/header.component.ts ***!
  \********************************************/
/*! exports provided: HeaderComponent */
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "HeaderComponent", function() { return HeaderComponent; });
/* harmony import */ var _angular_core__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @angular/core */ "./node_modules/@angular/core/fesm5/core.js");
/* harmony import */ var _services_auth_service__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ../services/auth.service */ "./src/app/services/auth.service.ts");
var __decorate = (undefined && undefined.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (undefined && undefined.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};


var HeaderComponent = /** @class */ (function () {
    function HeaderComponent(auth) {
        this.auth = auth;
    }
    HeaderComponent.prototype.ngOnInit = function () {
        var _this = this;
        this.authSubscription = this.auth.isAuth$.subscribe(function (auth) {
            _this.isAuth = auth;
        });
    };
    HeaderComponent.prototype.onLogout = function () {
        this.auth.logout();
    };
    HeaderComponent.prototype.ngOnDestroy = function () {
        this.authSubscription.unsubscribe();
    };
    HeaderComponent = __decorate([
        Object(_angular_core__WEBPACK_IMPORTED_MODULE_0__["Component"])({
            selector: 'app-header',
            template: __webpack_require__(/*! ./header.component.html */ "./src/app/header/header.component.html"),
            styles: [__webpack_require__(/*! ./header.component.scss */ "./src/app/header/header.component.scss")]
        }),
        __metadata("design:paramtypes", [_services_auth_service__WEBPACK_IMPORTED_MODULE_1__["AuthService"]])
    ], HeaderComponent);
    return HeaderComponent;
}());



/***/ }),

/***/ "./src/app/interceptors/auth-interceptor.ts":
/*!**************************************************!*\
  !*** ./src/app/interceptors/auth-interceptor.ts ***!
  \**************************************************/
/*! exports provided: AuthInterceptor */
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "AuthInterceptor", function() { return AuthInterceptor; });
/* harmony import */ var _angular_core__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @angular/core */ "./node_modules/@angular/core/fesm5/core.js");
/* harmony import */ var _services_auth_service__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ../services/auth.service */ "./src/app/services/auth.service.ts");
var __decorate = (undefined && undefined.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (undefined && undefined.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};


var AuthInterceptor = /** @class */ (function () {
    function AuthInterceptor(auth) {
        this.auth = auth;
    }
    AuthInterceptor.prototype.intercept = function (req, next) {
        var authToken = this.auth.getToken();
        var newRequest = req.clone({
            headers: req.headers.set('Authorization', 'Bearer ' + authToken)
        });
        return next.handle(newRequest);
    };
    AuthInterceptor = __decorate([
        Object(_angular_core__WEBPACK_IMPORTED_MODULE_0__["Injectable"])(),
        __metadata("design:paramtypes", [_services_auth_service__WEBPACK_IMPORTED_MODULE_1__["AuthService"]])
    ], AuthInterceptor);
    return AuthInterceptor;
}());



/***/ }),

/***/ "./src/app/models/Sauce.model.ts":
/*!***************************************!*\
  !*** ./src/app/models/Sauce.model.ts ***!
  \***************************************/
/*! exports provided: Sauce */
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "Sauce", function() { return Sauce; });
var Sauce = /** @class */ (function () {
    function Sauce() {
    }
    return Sauce;
}());



/***/ }),

/***/ "./src/app/sauce-form/sauce-form.component.html":
/*!******************************************************!*\
  !*** ./src/app/sauce-form/sauce-form.component.html ***!
  \******************************************************/
/*! no static exports found */
/***/ (function(module, exports) {

module.exports = "<mat-spinner *ngIf=\"loading\"></mat-spinner>\r\n<form [formGroup]=\"sauceForm\" *ngIf=\"!loading\">\r\n  <div class=\"form-group\">\r\n    <label for=\"name\">Name</label>\r\n    <input type=\"text\" class=\"form-control\" id=\"name\" formControlName=\"name\">\r\n  </div>\r\n  <div class=\"form-group\">\r\n    <label for=\"manufacturer\">Manufacturer</label>\r\n    <input type=\"text\" class=\"form-control\" id=\"manufacturer\" formControlName=\"manufacturer\">\r\n  </div>\r\n  <div class=\"form-group\">\r\n    <label for=\"description\">Description</label>\r\n    <textarea class=\"form-control\" id=\"description\" rows=\"5\" formControlName=\"description\"></textarea>\r\n  </div>\r\n  <div class=\"form-group\">\r\n    <input type=\"file\" accept=\"image/*\" #imageInput (change)=\"onFileAdded($event)\">\r\n    <button mat-raised-button color=\"primary\" (click)=\"imageInput.click()\">ADD IMAGE</button>\r\n    <img [src]=\"imagePreview\" *ngIf=\"imagePreview\" style=\"max-height: 100px;display:block;margin-top:10px\">\r\n  </div>\r\n  <div class=\"form-group\">\r\n    <label for=\"main-pepper\">Main Pepper Ingredient</label>\r\n    <input type=\"text\" class=\"form-control\" id=\"main-pepper\" formControlName=\"mainPepper\">\r\n  </div>\r\n  <div class=\"form-group\">\r\n    <label for=\"heat\">Heat</label>\r\n    <div class=\"heat-container\">\r\n      <input type=\"range\" class=\"custom-range heat-range\" min=\"1\" max=\"10\" id=\"heat\" formControlName=\"heat\">\r\n      <input type=\"number\" class=\"form-control heat-reading\" formControlName=\"heatValue\">\r\n    </div>\r\n  </div>\r\n  <button mat-raised-button color=\"primary\" (click)=\"onSubmit()\" [disabled]=\"sauceForm.invalid\">SUBMIT</button>\r\n</form>\r\n"

/***/ }),

/***/ "./src/app/sauce-form/sauce-form.component.scss":
/*!******************************************************!*\
  !*** ./src/app/sauce-form/sauce-form.component.scss ***!
  \******************************************************/
/*! no static exports found */
/***/ (function(module, exports) {

module.exports = "form {\n  margin: 2em auto;\n  max-width: 750px; }\n\n.heat-range {\n  width: 60%;\n  display: block; }\n\n.heat-container {\n  display: flex; }\n\n.heat-reading {\n  width: 5em;\n  margin-left: 1.5em;\n  background-color: white; }\n\ninput[type=\"file\"] {\n  display: none; }\n\n/*# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbInNyYy9hcHAvc2F1Y2UtZm9ybS9DOlxcVXNlcnNcXHl2ZW5vXFxEZXNrdG9wXFxQNlxcZnJvbnRlbmQvc3JjXFxhcHBcXHNhdWNlLWZvcm1cXHNhdWNlLWZvcm0uY29tcG9uZW50LnNjc3MiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6IkFBQUE7RUFDRSxpQkFBZ0I7RUFDaEIsaUJBQWdCLEVBQ2pCOztBQUVEO0VBQ0UsV0FBVTtFQUNWLGVBQWMsRUFDZjs7QUFFRDtFQUNFLGNBQWEsRUFDZDs7QUFFRDtFQUNFLFdBQVU7RUFDVixtQkFBa0I7RUFDbEIsd0JBQXVCLEVBQ3hCOztBQUVEO0VBQ0UsY0FBYSxFQUNkIiwiZmlsZSI6InNyYy9hcHAvc2F1Y2UtZm9ybS9zYXVjZS1mb3JtLmNvbXBvbmVudC5zY3NzIiwic291cmNlc0NvbnRlbnQiOlsiZm9ybSB7XHJcbiAgbWFyZ2luOiAyZW0gYXV0bztcclxuICBtYXgtd2lkdGg6IDc1MHB4O1xyXG59XHJcblxyXG4uaGVhdC1yYW5nZSB7XHJcbiAgd2lkdGg6IDYwJTtcclxuICBkaXNwbGF5OiBibG9jaztcclxufVxyXG5cclxuLmhlYXQtY29udGFpbmVyIHtcclxuICBkaXNwbGF5OiBmbGV4O1xyXG59XHJcblxyXG4uaGVhdC1yZWFkaW5nIHtcclxuICB3aWR0aDogNWVtO1xyXG4gIG1hcmdpbi1sZWZ0OiAxLjVlbTtcclxuICBiYWNrZ3JvdW5kLWNvbG9yOiB3aGl0ZTtcclxufVxyXG5cclxuaW5wdXRbdHlwZT1cImZpbGVcIl0ge1xyXG4gIGRpc3BsYXk6IG5vbmU7XHJcbn1cclxuIl19 */"

/***/ }),

/***/ "./src/app/sauce-form/sauce-form.component.ts":
/*!****************************************************!*\
  !*** ./src/app/sauce-form/sauce-form.component.ts ***!
  \****************************************************/
/*! exports provided: SauceFormComponent */
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "SauceFormComponent", function() { return SauceFormComponent; });
/* harmony import */ var _angular_core__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @angular/core */ "./node_modules/@angular/core/fesm5/core.js");
/* harmony import */ var _angular_forms__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @angular/forms */ "./node_modules/@angular/forms/fesm5/forms.js");
/* harmony import */ var _angular_router__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! @angular/router */ "./node_modules/@angular/router/fesm5/router.js");
/* harmony import */ var _services_sauces_service__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ../services/sauces.service */ "./src/app/services/sauces.service.ts");
/* harmony import */ var _models_Sauce_model__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ../models/Sauce.model */ "./src/app/models/Sauce.model.ts");
/* harmony import */ var _services_auth_service__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! ../services/auth.service */ "./src/app/services/auth.service.ts");
var __decorate = (undefined && undefined.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (undefined && undefined.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};






var SauceFormComponent = /** @class */ (function () {
    function SauceFormComponent(formBuilder, route, router, sauces, auth) {
        this.formBuilder = formBuilder;
        this.route = route;
        this.router = router;
        this.sauces = sauces;
        this.auth = auth;
    }
    SauceFormComponent.prototype.ngOnInit = function () {
        var _this = this;
        this.loading = true;
        this.route.params.subscribe(function (params) {
            if (!params.id) {
                _this.mode = 'new';
                _this.initEmptyForm();
                _this.loading = false;
            }
            else {
                _this.mode = 'edit';
                _this.sauces.getSauceById(params.id).then(function (sauce) {
                    _this.sauce = sauce;
                    _this.initModifyForm(sauce);
                    _this.loading = false;
                }).catch(function (error) {
                    _this.errorMsg = JSON.stringify(error);
                });
            }
        });
    };
    SauceFormComponent.prototype.initEmptyForm = function () {
        var _this = this;
        this.sauceForm = this.formBuilder.group({
            name: [null, _angular_forms__WEBPACK_IMPORTED_MODULE_1__["Validators"].required],
            manufacturer: [null, _angular_forms__WEBPACK_IMPORTED_MODULE_1__["Validators"].required],
            description: [null, _angular_forms__WEBPACK_IMPORTED_MODULE_1__["Validators"].required],
            image: [null, _angular_forms__WEBPACK_IMPORTED_MODULE_1__["Validators"].required],
            mainPepper: [null, _angular_forms__WEBPACK_IMPORTED_MODULE_1__["Validators"].required],
            heat: [1, _angular_forms__WEBPACK_IMPORTED_MODULE_1__["Validators"].required],
            heatValue: [{ value: 1, disabled: true }]
        });
        this.sauceForm.get('heat').valueChanges.subscribe(function (value) {
            _this.sauceForm.get('heatValue').setValue(value);
        });
    };
    SauceFormComponent.prototype.initModifyForm = function (sauce) {
        var _this = this;
        this.sauceForm = this.formBuilder.group({
            name: [this.sauce.name, _angular_forms__WEBPACK_IMPORTED_MODULE_1__["Validators"].required],
            manufacturer: [this.sauce.manufacturer, _angular_forms__WEBPACK_IMPORTED_MODULE_1__["Validators"].required],
            description: [this.sauce.description, _angular_forms__WEBPACK_IMPORTED_MODULE_1__["Validators"].required],
            image: [this.sauce.imageUrl, _angular_forms__WEBPACK_IMPORTED_MODULE_1__["Validators"].required],
            mainPepper: [this.sauce.mainPepper, _angular_forms__WEBPACK_IMPORTED_MODULE_1__["Validators"].required],
            heat: [this.sauce.heat, _angular_forms__WEBPACK_IMPORTED_MODULE_1__["Validators"].required],
            heatValue: [{ value: this.sauce.heat, disabled: true }]
        });
        this.sauceForm.get('heat').valueChanges.subscribe(function (value) {
            _this.sauceForm.get('heatValue').setValue(value);
        });
        this.imagePreview = this.sauce.imageUrl;
    };
    SauceFormComponent.prototype.onSubmit = function () {
        var _this = this;
        this.loading = true;
        var newSauce = new _models_Sauce_model__WEBPACK_IMPORTED_MODULE_4__["Sauce"]();
        newSauce.name = this.sauceForm.get('name').value;
        newSauce.manufacturer = this.sauceForm.get('manufacturer').value;
        newSauce.description = this.sauceForm.get('description').value;
        newSauce.mainPepper = this.sauceForm.get('mainPepper').value;
        newSauce.heat = this.sauceForm.get('heat').value;
        newSauce.userId = this.auth.getUserId();
        if (this.mode === 'new') {
            this.sauces.createSauce(newSauce, this.sauceForm.get('image').value).then(function (response) {
                console.log(response.message);
                _this.loading = false;
                _this.router.navigate(['/sauces']);
            }).catch(function (error) {
                console.error(error);
                _this.loading = false;
                _this.errorMsg = error.message;
            });
        }
        else if (this.mode === 'edit') {
            this.sauces.modifySauce(this.sauce._id, newSauce, this.sauceForm.get('image').value).then(function (response) {
                console.log(response.message);
                _this.loading = false;
                _this.router.navigate(['/sauces']);
            }).catch(function (error) {
                console.error(error);
                _this.loading = false;
                _this.errorMsg = error.message;
            });
        }
    };
    SauceFormComponent.prototype.onFileAdded = function (event) {
        var _this = this;
        var file = event.target.files[0];
        this.sauceForm.get('image').setValue(file);
        this.sauceForm.updateValueAndValidity();
        var reader = new FileReader();
        reader.onload = function () {
            _this.imagePreview = reader.result;
        };
        reader.readAsDataURL(file);
    };
    SauceFormComponent = __decorate([
        Object(_angular_core__WEBPACK_IMPORTED_MODULE_0__["Component"])({
            selector: 'app-sauce-form',
            template: __webpack_require__(/*! ./sauce-form.component.html */ "./src/app/sauce-form/sauce-form.component.html"),
            styles: [__webpack_require__(/*! ./sauce-form.component.scss */ "./src/app/sauce-form/sauce-form.component.scss")]
        }),
        __metadata("design:paramtypes", [_angular_forms__WEBPACK_IMPORTED_MODULE_1__["FormBuilder"],
            _angular_router__WEBPACK_IMPORTED_MODULE_2__["ActivatedRoute"],
            _angular_router__WEBPACK_IMPORTED_MODULE_2__["Router"],
            _services_sauces_service__WEBPACK_IMPORTED_MODULE_3__["SaucesService"],
            _services_auth_service__WEBPACK_IMPORTED_MODULE_5__["AuthService"]])
    ], SauceFormComponent);
    return SauceFormComponent;
}());



/***/ }),

/***/ "./src/app/sauce-list/sauce-list.component.html":
/*!******************************************************!*\
  !*** ./src/app/sauce-list/sauce-list.component.html ***!
  \******************************************************/
/*! no static exports found */
/***/ (function(module, exports) {

module.exports = "<mat-spinner *ngIf=\"loading\"></mat-spinner>\r\n<p *ngIf=\"!loading && sauces.length <= 0\">\r\n  No sauces to display!\r\n</p>\r\n<p class=\"list-title\" *ngIf=\"!loading && sauces.length > 0\">THE SAUCES</p>\r\n<div class=\"sauce-list\" *ngIf=\"!loading && sauces.length  > 0\">\r\n  <div class=\"sauce-list-item\" *ngFor=\"let sauce of sauces\" (click)=\"onClickSauce(sauce._id)\">\r\n    <img [src]=\"sauce.imageUrl\">\r\n    <h4>{{ sauce.name | uppercase }}</h4>\r\n    <p>Heat: {{ sauce.heat }}/10</p>\r\n  </div>\r\n</div>\r\n"

/***/ }),

/***/ "./src/app/sauce-list/sauce-list.component.scss":
/*!******************************************************!*\
  !*** ./src/app/sauce-list/sauce-list.component.scss ***!
  \******************************************************/
/*! no static exports found */
/***/ (function(module, exports) {

module.exports = ".sauce-list {\n  display: flex;\n  justify-content: space-around;\n  flex-wrap: wrap; }\n\n.sauce-list-item {\n  text-align: center;\n  width: 220px;\n  transition: all 0.1s ease-in-out;\n  cursor: pointer; }\n\n.sauce-list-item img {\n    max-width: 200px;\n    max-height: 250px; }\n\n.sauce-list-item h4 {\n    margin: 0;\n    font-weight: 500; }\n\n.sauce-list-item p {\n    margin: 0; }\n\n.sauce-list-item:hover {\n    -webkit-transform: scale(1.05);\n            transform: scale(1.05);\n    box-shadow: 1px 1px 20px rgba(120, 120, 120, 0.3); }\n\n.list-title {\n  text-align: center;\n  margin: 2em auto; }\n\n/*# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbInNyYy9hcHAvc2F1Y2UtbGlzdC9DOlxcVXNlcnNcXHl2ZW5vXFxEZXNrdG9wXFxQNlxcZnJvbnRlbmQvc3JjXFxhcHBcXHNhdWNlLWxpc3RcXHNhdWNlLWxpc3QuY29tcG9uZW50LnNjc3MiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6IkFBQUE7RUFDRSxjQUFhO0VBQ2IsOEJBQTZCO0VBQzdCLGdCQUFlLEVBQ2hCOztBQUVEO0VBQ0UsbUJBQWtCO0VBQ2xCLGFBQVk7RUFZWixpQ0FBZ0M7RUFDaEMsZ0JBQWUsRUFLaEI7O0FBcEJEO0lBSUksaUJBQWdCO0lBQ2hCLGtCQUFpQixFQUNsQjs7QUFOSDtJQVFJLFVBQVM7SUFDVCxpQkFBZ0IsRUFDakI7O0FBVkg7SUFZSSxVQUFTLEVBQ1Y7O0FBYkg7SUFpQkksK0JBQXNCO1lBQXRCLHVCQUFzQjtJQUN0QixrREFBaUQsRUFDbEQ7O0FBR0g7RUFDRSxtQkFBa0I7RUFDbEIsaUJBQWdCLEVBQ2pCIiwiZmlsZSI6InNyYy9hcHAvc2F1Y2UtbGlzdC9zYXVjZS1saXN0LmNvbXBvbmVudC5zY3NzIiwic291cmNlc0NvbnRlbnQiOlsiLnNhdWNlLWxpc3Qge1xyXG4gIGRpc3BsYXk6IGZsZXg7XHJcbiAganVzdGlmeS1jb250ZW50OiBzcGFjZS1hcm91bmQ7XHJcbiAgZmxleC13cmFwOiB3cmFwO1xyXG59XHJcblxyXG4uc2F1Y2UtbGlzdC1pdGVtIHtcclxuICB0ZXh0LWFsaWduOiBjZW50ZXI7XHJcbiAgd2lkdGg6IDIyMHB4O1xyXG4gIGltZyB7XHJcbiAgICBtYXgtd2lkdGg6IDIwMHB4O1xyXG4gICAgbWF4LWhlaWdodDogMjUwcHg7XHJcbiAgfVxyXG4gIGg0IHtcclxuICAgIG1hcmdpbjogMDtcclxuICAgIGZvbnQtd2VpZ2h0OiA1MDA7XHJcbiAgfVxyXG4gIHAge1xyXG4gICAgbWFyZ2luOiAwO1xyXG4gIH1cclxuICB0cmFuc2l0aW9uOiBhbGwgMC4xcyBlYXNlLWluLW91dDtcclxuICBjdXJzb3I6IHBvaW50ZXI7XHJcbiAgJjpob3ZlciB7XHJcbiAgICB0cmFuc2Zvcm06IHNjYWxlKDEuMDUpO1xyXG4gICAgYm94LXNoYWRvdzogMXB4IDFweCAyMHB4IHJnYmEoMTIwLCAxMjAsIDEyMCwgMC4zKTtcclxuICB9XHJcbn1cclxuXHJcbi5saXN0LXRpdGxlIHtcclxuICB0ZXh0LWFsaWduOiBjZW50ZXI7XHJcbiAgbWFyZ2luOiAyZW0gYXV0bztcclxufVxyXG4iXX0= */"

/***/ }),

/***/ "./src/app/sauce-list/sauce-list.component.ts":
/*!****************************************************!*\
  !*** ./src/app/sauce-list/sauce-list.component.ts ***!
  \****************************************************/
/*! exports provided: SauceListComponent */
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "SauceListComponent", function() { return SauceListComponent; });
/* harmony import */ var _angular_core__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @angular/core */ "./node_modules/@angular/core/fesm5/core.js");
/* harmony import */ var _services_sauces_service__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ../services/sauces.service */ "./src/app/services/sauces.service.ts");
/* harmony import */ var _angular_router__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! @angular/router */ "./node_modules/@angular/router/fesm5/router.js");
var __decorate = (undefined && undefined.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (undefined && undefined.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};



var SauceListComponent = /** @class */ (function () {
    function SauceListComponent(sauce, router) {
        this.sauce = sauce;
        this.router = router;
    }
    SauceListComponent.prototype.ngOnInit = function () {
        var _this = this;
        this.loading = true;
        this.sauceSub = this.sauce.sauces$.subscribe(function (sauces) {
            _this.sauces = sauces;
            _this.loading = false;
            _this.errorMsg = null;
        }, function (error) {
            _this.errorMsg = JSON.stringify(error);
            _this.loading = false;
        });
        this.sauce.getSauces();
    };
    SauceListComponent.prototype.onClickSauce = function (id) {
        this.router.navigate(['sauce', id]);
    };
    SauceListComponent = __decorate([
        Object(_angular_core__WEBPACK_IMPORTED_MODULE_0__["Component"])({
            selector: 'app-sauce-list',
            template: __webpack_require__(/*! ./sauce-list.component.html */ "./src/app/sauce-list/sauce-list.component.html"),
            styles: [__webpack_require__(/*! ./sauce-list.component.scss */ "./src/app/sauce-list/sauce-list.component.scss")]
        }),
        __metadata("design:paramtypes", [_services_sauces_service__WEBPACK_IMPORTED_MODULE_1__["SaucesService"],
            _angular_router__WEBPACK_IMPORTED_MODULE_2__["Router"]])
    ], SauceListComponent);
    return SauceListComponent;
}());



/***/ }),

/***/ "./src/app/services/auth-guard.service.ts":
/*!************************************************!*\
  !*** ./src/app/services/auth-guard.service.ts ***!
  \************************************************/
/*! exports provided: AuthGuard */
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "AuthGuard", function() { return AuthGuard; });
/* harmony import */ var _angular_core__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @angular/core */ "./node_modules/@angular/core/fesm5/core.js");
/* harmony import */ var _angular_router__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @angular/router */ "./node_modules/@angular/router/fesm5/router.js");
/* harmony import */ var rxjs__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! rxjs */ "./node_modules/rxjs/_esm5/index.js");
/* harmony import */ var _auth_service__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ./auth.service */ "./src/app/services/auth.service.ts");
var __decorate = (undefined && undefined.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (undefined && undefined.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};




var AuthGuard = /** @class */ (function () {
    function AuthGuard(auth, router) {
        this.auth = auth;
        this.router = router;
    }
    AuthGuard.prototype.canActivate = function (route, state) {
        var _this = this;
        return rxjs__WEBPACK_IMPORTED_MODULE_2__["Observable"].create(function (observer) {
            _this.auth.isAuth$.subscribe(function (auth) {
                if (auth) {
                    observer.next(true);
                }
                else {
                    _this.router.navigate(['/login']);
                }
            });
        });
    };
    AuthGuard = __decorate([
        Object(_angular_core__WEBPACK_IMPORTED_MODULE_0__["Injectable"])(),
        __metadata("design:paramtypes", [_auth_service__WEBPACK_IMPORTED_MODULE_3__["AuthService"],
            _angular_router__WEBPACK_IMPORTED_MODULE_1__["Router"]])
    ], AuthGuard);
    return AuthGuard;
}());



/***/ }),

/***/ "./src/app/services/auth.service.ts":
/*!******************************************!*\
  !*** ./src/app/services/auth.service.ts ***!
  \******************************************/
/*! exports provided: AuthService */
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "AuthService", function() { return AuthService; });
/* harmony import */ var _angular_core__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @angular/core */ "./node_modules/@angular/core/fesm5/core.js");
/* harmony import */ var _angular_common_http__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @angular/common/http */ "./node_modules/@angular/common/fesm5/http.js");
/* harmony import */ var rxjs__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! rxjs */ "./node_modules/rxjs/_esm5/index.js");
/* harmony import */ var _angular_router__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! @angular/router */ "./node_modules/@angular/router/fesm5/router.js");
var __decorate = (undefined && undefined.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (undefined && undefined.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};




var AuthService = /** @class */ (function () {
    function AuthService(http, router) {
        this.http = http;
        this.router = router;
        this.isAuth$ = new rxjs__WEBPACK_IMPORTED_MODULE_2__["BehaviorSubject"](false);
    }
    AuthService.prototype.createUser = function (email, password) {
        var _this = this;
        return new Promise(function (resolve, reject) {
            _this.http.post('http://localhost:3000/api/auth/signup', { email: email, password: password }).subscribe(function (response) {
                resolve(response);
            }, function (error) {
                reject(error);
            });
        });
    };
    AuthService.prototype.getToken = function () {
        return this.authToken;
    };
    AuthService.prototype.getUserId = function () {
        return this.userId;
    };
    AuthService.prototype.loginUser = function (email, password) {
        var _this = this;
        return new Promise(function (resolve, reject) {
            _this.http.post('http://localhost:3000/api/auth/login', { email: email, password: password }).subscribe(function (response) {
                _this.userId = response.userId;
                _this.authToken = response.token;
                _this.isAuth$.next(true);
                resolve();
            }, function (error) {
                reject(error);
            });
        });
    };
    AuthService.prototype.logout = function () {
        this.authToken = null;
        this.userId = null;
        this.isAuth$.next(false);
        this.router.navigate(['login']);
    };
    AuthService = __decorate([
        Object(_angular_core__WEBPACK_IMPORTED_MODULE_0__["Injectable"])({
            providedIn: 'root'
        }),
        __metadata("design:paramtypes", [_angular_common_http__WEBPACK_IMPORTED_MODULE_1__["HttpClient"],
            _angular_router__WEBPACK_IMPORTED_MODULE_3__["Router"]])
    ], AuthService);
    return AuthService;
}());



/***/ }),

/***/ "./src/app/services/sauces.service.ts":
/*!********************************************!*\
  !*** ./src/app/services/sauces.service.ts ***!
  \********************************************/
/*! exports provided: SaucesService */
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "SaucesService", function() { return SaucesService; });
/* harmony import */ var _angular_core__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @angular/core */ "./node_modules/@angular/core/fesm5/core.js");
/* harmony import */ var rxjs__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! rxjs */ "./node_modules/rxjs/_esm5/index.js");
/* harmony import */ var _angular_common_http__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! @angular/common/http */ "./node_modules/@angular/common/fesm5/http.js");
/* harmony import */ var _auth_service__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ./auth.service */ "./src/app/services/auth.service.ts");
var __decorate = (undefined && undefined.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (undefined && undefined.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};




var SaucesService = /** @class */ (function () {
    function SaucesService(http, auth) {
        this.http = http;
        this.auth = auth;
        this.sauces$ = new rxjs__WEBPACK_IMPORTED_MODULE_1__["Subject"]();
        this.tempSauces = [
            {
                _id: 'eizomfhazo',
                name: 'The Last Dab',
                manufacturer: 'Heatonist',
                description: 'CAUTION! The Last Dab—the hottest sauce on Hot Ones, known for turning guests and fans alike into stuttering, fire-breathing lunatics—just got even crazier. The Last Dab first took the world by storm as the only sauce made with Smokin\' Ed Currie\'s infamous "Pepper X." This XX-rated edition gets its one-two punch of heat from addition of the equally lethal "Chocolate Pepper X." All you need is a dab to light the inferno and experience the Hot Ones tradition.',
                heat: 10,
                likes: 100,
                dislikes: 0,
                imageUrl: 'https://cdn.shopify.com/s/files/1/2086/9287/products/LAstdabReduxx_1024x1024-1_1024x1024.jpg?v=1527778720',
                mainPepper: 'Pepper X',
                usersLiked: [],
                usersDisliked: []
            },
            {
                _id: 'oimhoiohmhoih',
                name: 'Los Calientes',
                manufacturer: 'Heatonist',
                description: 'Hot Ones is the show where celebrities divulge their deepest secrets while eating progressively hotter wings. The middle of the lineup is where hot sauce magic happens—the perfect sweet spot between maximum flavor and pleasing heat. Inspired by our favorite Cali-Mex flavors, Los Calientes surfs over the palate with a punchy, smoky blend...',
                heat: 5,
                likes: 100,
                dislikes: 0,
                imageUrl: 'https://cdn.shopify.com/s/files/1/2086/9287/products/LOS_CALIENTES1_1024x1024.jpg?v=1527709467',
                mainPepper: 'Serrano',
                usersLiked: [],
                usersDisliked: []
            },
            {
                _id: 'oimjoijlhui',
                name: 'Black Garlic',
                manufacturer: 'Bravado Spice Company',
                description: 'Team Bravado is back at it with an elevated offering where Carolina Reaper meets aged black garlic. The sweetness of the slowly cooked garlic tempers the initial bitter burn of the Reaper, but not for long... This is a biting hot sauce you\'ll want in marinades, sauces, dressings, and on those garlic wings! ',
                heat: 6,
                likes: 100,
                dislikes: 0,
                imageUrl: 'https://cdn.shopify.com/s/files/1/2086/9287/products/bravado-blackgarlichotsauce_1024x1024.jpg?v=1527270029',
                mainPepper: 'Carolina Reaper',
                usersLiked: [],
                usersDisliked: []
            },
            {
                _id: 'sildjhv',
                name: 'Smoked Onion',
                manufacturer: 'Butterfly Bakery',
                description: 'The makers at Butterfly Bakery smoke Vermont onions with maplewood to mix with red jalapeños for this sweet and tangy sauce. Great on everything from bagels lox & cream cheese to hummus to pork and whatever else you can name. The medium heat level makes it the perfect smoky sauce for anyone!',
                heat: 3,
                likes: 100,
                dislikes: 0,
                imageUrl: 'https://cdn.shopify.com/s/files/1/2086/9287/products/smokedonion1_1024x1024_copy_1024x1024.jpg?v=1538413599',
                mainPepper: 'Jalapeños',
                usersLiked: [],
                usersDisliked: []
            },
            {
                _id: 'eroimfgjlfh',
                name: 'Blair\'s Ultra Death Sauce',
                manufacturer: 'Blair\'s',
                description: 'Blair\'s Ultra Death has established itself as a bit of a legend within the hot sauce world.\n' +
                    '\n' +
                    'If there\'s one thing that creator Blair Lazar does well it\'s retaining the flavour in his super-hot sauces. They\'ll melt your face off for sure, but despite the extract they still taste damned fine.\n' +
                    '\n' +
                    'Just to emphasise the seriousness of the heat we\'re dealing with here, all Blair\'s super-hot sauces in the Death range now come in a nifty coffin box with his trademark skull keyring attached to the bottle.',
                heat: 9,
                likes: 100,
                dislikes: 0,
                imageUrl: 'https://www.chilliworld.com/content/images/thumbs/0000827_blairs-ultra-death-sauce-in-a-coffin_550.jpeg',
                mainPepper: 'Carolina Reaper',
                usersLiked: [],
                usersDisliked: []
            }
        ];
    }
    SaucesService.prototype.getSauces = function () {
        var _this = this;
        this.http.get('http://localhost:3000/api/sauces').subscribe(function (sauces) {
            _this.sauces$.next(sauces);
        }, function (error) {
            _this.sauces$.next([]);
            console.error(error);
        });
    };
    SaucesService.prototype.getSauceById = function (id) {
        var _this = this;
        return new Promise(function (resolve, reject) {
            _this.http.get('http://localhost:3000/api/sauces/' + id).subscribe(function (sauce) {
                resolve(sauce);
            }, function (error) {
                reject(error);
            });
        });
    };
    SaucesService.prototype.likeSauce = function (id, like) {
        var _this = this;
        return new Promise(function (resolve, reject) {
            _this.http.post('http://localhost:3000/api/sauces/' + id + '/like', {
                userId: _this.auth.getUserId(),
                like: like ? 1 : 0
            })
                .subscribe(function (response) {
                resolve(like);
            }, function (error) {
                reject(error);
            });
        });
    };
    SaucesService.prototype.dislikeSauce = function (id, dislike) {
        var _this = this;
        return new Promise(function (resolve, reject) {
            _this.http.post('http://localhost:3000/api/sauces/' + id + '/like', {
                userId: _this.auth.getUserId(),
                like: dislike ? -1 : 0
            })
                .subscribe(function (response) {
                resolve(dislike);
            }, function (error) {
                reject(error);
            });
        });
    };
    SaucesService.prototype.createSauce = function (sauce, image) {
        var _this = this;
        return new Promise(function (resolve, reject) {
            var formData = new FormData();
            formData.append('sauce', JSON.stringify(sauce));
            formData.append('image', image);
            _this.http.post('http://localhost:3000/api/sauces', formData).subscribe(function (response) {
                resolve(response);
            }, function (error) {
                reject(error);
            });
        });
    };
    SaucesService.prototype.modifySauce = function (id, sauce, image) {
        var _this = this;
        return new Promise(function (resolve, reject) {
            if (typeof image === 'string') {
                _this.http.put('http://localhost:3000/api/sauces/' + id, sauce).subscribe(function (response) {
                    resolve(response);
                }, function (error) {
                    reject(error);
                });
            }
            else {
                var formData = new FormData();
                formData.append('sauce', JSON.stringify(sauce));
                formData.append('image', image);
                _this.http.put('http://localhost:3000/api/sauces/' + id, formData).subscribe(function (response) {
                    resolve(response);
                }, function (error) {
                    reject(error);
                });
            }
        });
    };
    SaucesService.prototype.deleteSauce = function (id) {
        var _this = this;
        return new Promise(function (resolve, reject) {
            _this.http.delete('http://localhost:3000/api/sauces/' + id).subscribe(function (response) {
                resolve(response);
            }, function (error) {
                reject(error);
            });
        });
    };
    SaucesService = __decorate([
        Object(_angular_core__WEBPACK_IMPORTED_MODULE_0__["Injectable"])({
            providedIn: 'root'
        }),
        __metadata("design:paramtypes", [_angular_common_http__WEBPACK_IMPORTED_MODULE_2__["HttpClient"],
            _auth_service__WEBPACK_IMPORTED_MODULE_3__["AuthService"]])
    ], SaucesService);
    return SaucesService;
}());



/***/ }),

/***/ "./src/app/single-sauce/single-sauce.component.html":
/*!**********************************************************!*\
  !*** ./src/app/single-sauce/single-sauce.component.html ***!
  \**********************************************************/
/*! no static exports found */
/***/ (function(module, exports) {

module.exports = "<mat-spinner *ngIf=\"loading\"></mat-spinner>\r\n<div class=\"sauce-container\" *ngIf=\"!loading\">\r\n  <img [src]=\"sauce?.imageUrl\" alt=\"\">\r\n  <div class=\"sauce-info\">\r\n    <h1 class=\"sauce-name\">{{ sauce?.name }}</h1>\r\n    <p class=\"manufacturer\">by {{ sauce?.manufacturer }}</p>\r\n    <h3>Description</h3>\r\n    <p>{{ sauce.description }}</p>\r\n    <div class=\"like-buttons\" *ngIf=\"!likePending\">\r\n      <div class=\"likes\">\r\n        <i [ngClass]=\"{ 'fas liked': liked, 'far': !liked, 'disabled': disliked }\" class=\"like fa-thumbs-up fa-lg\" (click)=\"onLike()\"></i>\r\n        <span>{{ sauce.likes }}</span>\r\n      </div>\r\n      <div class=\"dislikes\">\r\n        <i [ngClass]=\"{ 'fas disliked': disliked, 'far': !disliked, 'disabled': liked }\" class=\"dislike fa-thumbs-down fa-lg\" (click)=\"onDislike()\"></i>\r\n        <span>{{ sauce.dislikes }}</span>\r\n      </div>\r\n    </div>\r\n    <div class=\"like-pending\" *ngIf=\"likePending\">\r\n      <mat-spinner class=\"white-spinner\"></mat-spinner>\r\n    </div>\r\n    <div class=\"control-buttons\">\r\n      <button mat-raised-button (click)=\"onBack()\">BACK</button>\r\n      <button mat-raised-button color=\"primary\" (click)=\"onModify()\" *ngIf=\"userId === sauce.userId\">MODIFY</button>\r\n      <button mat-raised-button color=\"warn\" (click)=\"onDelete()\" *ngIf=\"userId === sauce.userId\">DELETE</button>\r\n    </div>\r\n  </div>\r\n</div>\r\n"

/***/ }),

/***/ "./src/app/single-sauce/single-sauce.component.scss":
/*!**********************************************************!*\
  !*** ./src/app/single-sauce/single-sauce.component.scss ***!
  \**********************************************************/
/*! no static exports found */
/***/ (function(module, exports) {

module.exports = ".sauce-container {\n  display: flex; }\n  .sauce-container img {\n    max-height: 70vh;\n    flex: 1; }\n  .sauce-info {\n  padding: 40px 20px;\n  flex: 1; }\n  .manufacturer {\n  margin: 0; }\n  .sauce-name {\n  margin: 0; }\n  .like-buttons {\n  display: flex; }\n  .like-buttons i {\n    margin-right: 0.5em;\n    cursor: pointer; }\n  .likes, .dislikes {\n  margin: 0 0.4em; }\n  .liked {\n  color: #33db00; }\n  .disliked {\n  color: #db3300; }\n  .like:hover {\n  color: #33db00; }\n  .dislike {\n  -webkit-transform: scaleX(-1) translateY(5px);\n          transform: scaleX(-1) translateY(5px); }\n  .dislike:hover {\n    color: #db3300; }\n  .disabled {\n  cursor: none;\n  color: #bebebe; }\n  .disabled:hover {\n    color: #bebebe; }\n  .control-buttons button {\n  margin: 1em 1em 0 0; }\n\n/*# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbInNyYy9hcHAvc2luZ2xlLXNhdWNlL0M6XFxVc2Vyc1xceXZlbm9cXERlc2t0b3BcXFA2XFxmcm9udGVuZC9zcmNcXGFwcFxcc2luZ2xlLXNhdWNlXFxzaW5nbGUtc2F1Y2UuY29tcG9uZW50LnNjc3MiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6IkFBQUE7RUFDRSxjQUFhLEVBS2Q7RUFORDtJQUdJLGlCQUFnQjtJQUNoQixRQUFPLEVBQ1I7RUFHSDtFQUNFLG1CQUFrQjtFQUNsQixRQUFPLEVBQ1I7RUFFRDtFQUNFLFVBQVMsRUFDVjtFQUVEO0VBQ0UsVUFBUyxFQUNWO0VBRUQ7RUFDRSxjQUFhLEVBS2Q7RUFORDtJQUdJLG9CQUFtQjtJQUNuQixnQkFBZSxFQUNoQjtFQUdIO0VBQ0UsZ0JBQWUsRUFDaEI7RUFFRDtFQUNFLGVBQTBCLEVBQzNCO0VBRUQ7RUFDRSxlQUEwQixFQUMzQjtFQUVEO0VBRUksZUFBMEIsRUFDM0I7RUFHSDtFQUNFLDhDQUFxQztVQUFyQyxzQ0FBcUMsRUFJdEM7RUFMRDtJQUdJLGVBQTBCLEVBQzNCO0VBR0g7RUFDRSxhQUFZO0VBSVosZUFBNkIsRUFDOUI7RUFORDtJQUdJLGVBQTZCLEVBQzlCO0VBSUg7RUFFSSxvQkFBbUIsRUFDcEIiLCJmaWxlIjoic3JjL2FwcC9zaW5nbGUtc2F1Y2Uvc2luZ2xlLXNhdWNlLmNvbXBvbmVudC5zY3NzIiwic291cmNlc0NvbnRlbnQiOlsiLnNhdWNlLWNvbnRhaW5lciB7XHJcbiAgZGlzcGxheTogZmxleDtcclxuICBpbWcge1xyXG4gICAgbWF4LWhlaWdodDogNzB2aDtcclxuICAgIGZsZXg6IDE7XHJcbiAgfVxyXG59XHJcblxyXG4uc2F1Y2UtaW5mbyB7XHJcbiAgcGFkZGluZzogNDBweCAyMHB4O1xyXG4gIGZsZXg6IDE7XHJcbn1cclxuXHJcbi5tYW51ZmFjdHVyZXIge1xyXG4gIG1hcmdpbjogMDtcclxufVxyXG5cclxuLnNhdWNlLW5hbWUge1xyXG4gIG1hcmdpbjogMDtcclxufVxyXG5cclxuLmxpa2UtYnV0dG9ucyB7XHJcbiAgZGlzcGxheTogZmxleDtcclxuICBpIHtcclxuICAgIG1hcmdpbi1yaWdodDogMC41ZW07XHJcbiAgICBjdXJzb3I6IHBvaW50ZXI7XHJcbiAgfVxyXG59XHJcblxyXG4ubGlrZXMsIC5kaXNsaWtlcyB7XHJcbiAgbWFyZ2luOiAwIDAuNGVtO1xyXG59XHJcblxyXG4ubGlrZWQge1xyXG4gIGNvbG9yOiByZ2JhKDUxLCAyMTksIDAsIDEpO1xyXG59XHJcblxyXG4uZGlzbGlrZWQge1xyXG4gIGNvbG9yOiByZ2JhKDIxOSwgNTEsIDAsIDEpO1xyXG59XHJcblxyXG4ubGlrZSB7XHJcbiAgJjpob3ZlciB7XHJcbiAgICBjb2xvcjogcmdiYSg1MSwgMjE5LCAwLCAxKTtcclxuICB9XHJcbn1cclxuXHJcbi5kaXNsaWtlIHtcclxuICB0cmFuc2Zvcm06IHNjYWxlWCgtMSkgdHJhbnNsYXRlWSg1cHgpO1xyXG4gICY6aG92ZXIge1xyXG4gICAgY29sb3I6IHJnYmEoMjE5LCA1MSwgMCwgMSk7XHJcbiAgfVxyXG59XHJcblxyXG4uZGlzYWJsZWQge1xyXG4gIGN1cnNvcjogbm9uZTtcclxuICAmOmhvdmVyIHtcclxuICAgIGNvbG9yOiByZ2JhKDE5MCwgMTkwLCAxOTAsIDEpO1xyXG4gIH1cclxuICBjb2xvcjogcmdiYSgxOTAsIDE5MCwgMTkwLCAxKTtcclxufVxyXG5cclxuLmNvbnRyb2wtYnV0dG9ucyB7XHJcbiAgYnV0dG9uIHtcclxuICAgIG1hcmdpbjogMWVtIDFlbSAwIDA7XHJcbiAgfVxyXG59XHJcbiJdfQ== */"

/***/ }),

/***/ "./src/app/single-sauce/single-sauce.component.ts":
/*!********************************************************!*\
  !*** ./src/app/single-sauce/single-sauce.component.ts ***!
  \********************************************************/
/*! exports provided: SingleSauceComponent */
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "SingleSauceComponent", function() { return SingleSauceComponent; });
/* harmony import */ var _angular_core__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @angular/core */ "./node_modules/@angular/core/fesm5/core.js");
/* harmony import */ var _services_sauces_service__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ../services/sauces.service */ "./src/app/services/sauces.service.ts");
/* harmony import */ var _angular_router__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! @angular/router */ "./node_modules/@angular/router/fesm5/router.js");
/* harmony import */ var _services_auth_service__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ../services/auth.service */ "./src/app/services/auth.service.ts");
var __decorate = (undefined && undefined.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (undefined && undefined.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};




var SingleSauceComponent = /** @class */ (function () {
    function SingleSauceComponent(sauces, route, auth, router) {
        this.sauces = sauces;
        this.route = route;
        this.auth = auth;
        this.router = router;
    }
    SingleSauceComponent.prototype.ngOnInit = function () {
        var _this = this;
        this.userId = this.auth.getUserId();
        this.loading = true;
        this.route.params.subscribe(function (params) {
            _this.sauces.getSauceById(params.id).then(function (sauce) {
                _this.sauce = sauce;
                _this.loading = false;
                if (sauce.usersLiked.find(function (user) { return user === _this.userId; })) {
                    _this.liked = true;
                }
                else if (sauce.usersDisliked.find(function (user) { return user === _this.userId; })) {
                    _this.disliked = true;
                }
            });
        });
        this.userId = this.auth.getUserId();
    };
    SingleSauceComponent.prototype.onLike = function () {
        var _this = this;
        if (this.disliked) {
            return 0;
        }
        this.likePending = true;
        this.sauces.likeSauce(this.sauce._id, !this.liked).then(function (liked) {
            _this.likePending = false;
            _this.liked = liked;
            if (liked) {
                _this.sauce.likes++;
            }
            else {
                _this.sauce.likes--;
            }
        });
    };
    SingleSauceComponent.prototype.onDislike = function () {
        var _this = this;
        if (this.liked) {
            return 0;
        }
        this.likePending = true;
        this.sauces.dislikeSauce(this.sauce._id, !this.disliked).then(function (disliked) {
            _this.likePending = false;
            _this.disliked = disliked;
            if (disliked) {
                _this.sauce.dislikes++;
            }
            else {
                _this.sauce.dislikes--;
            }
        });
    };
    SingleSauceComponent.prototype.onBack = function () {
        this.router.navigate(['/sauces']);
    };
    SingleSauceComponent.prototype.onModify = function () {
        this.router.navigate(['/modify-sauce', this.sauce._id]);
    };
    SingleSauceComponent.prototype.onDelete = function () {
        var _this = this;
        this.loading = true;
        this.sauces.deleteSauce(this.sauce._id).then(function (response) {
            console.log(response.message);
            _this.loading = false;
            _this.router.navigate(['/sauces']);
        }).catch(function (error) {
            _this.loading = false;
            _this.errorMessage = error.message;
            console.error(error);
        });
    };
    SingleSauceComponent = __decorate([
        Object(_angular_core__WEBPACK_IMPORTED_MODULE_0__["Component"])({
            selector: 'app-single-sauce',
            template: __webpack_require__(/*! ./single-sauce.component.html */ "./src/app/single-sauce/single-sauce.component.html"),
            styles: [__webpack_require__(/*! ./single-sauce.component.scss */ "./src/app/single-sauce/single-sauce.component.scss")]
        }),
        __metadata("design:paramtypes", [_services_sauces_service__WEBPACK_IMPORTED_MODULE_1__["SaucesService"],
            _angular_router__WEBPACK_IMPORTED_MODULE_2__["ActivatedRoute"],
            _services_auth_service__WEBPACK_IMPORTED_MODULE_3__["AuthService"],
            _angular_router__WEBPACK_IMPORTED_MODULE_2__["Router"]])
    ], SingleSauceComponent);
    return SingleSauceComponent;
}());



/***/ }),

/***/ "./src/environments/environment.ts":
/*!*****************************************!*\
  !*** ./src/environments/environment.ts ***!
  \*****************************************/
/*! exports provided: environment */
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "environment", function() { return environment; });
// This file can be replaced during build by using the `fileReplacements` array.
// `ng build --prod` replaces `environment.ts` with `environment.prod.ts`.
// The list of file replacements can be found in `angular.json`.
var environment = {
    production: false
};
/*
 * For easier debugging in development mode, you can import the following file
 * to ignore zone related error stack frames such as `zone.run`, `zoneDelegate.invokeTask`.
 *
 * This import should be commented out in production mode because it will have a negative impact
 * on performance if an error is thrown.
 */
// import 'zone.js/dist/zone-error';  // Included with Angular CLI.


/***/ }),

/***/ "./src/main.ts":
/*!*********************!*\
  !*** ./src/main.ts ***!
  \*********************/
/*! no exports provided */
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony import */ var _angular_core__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @angular/core */ "./node_modules/@angular/core/fesm5/core.js");
/* harmony import */ var _angular_platform_browser_dynamic__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @angular/platform-browser-dynamic */ "./node_modules/@angular/platform-browser-dynamic/fesm5/platform-browser-dynamic.js");
/* harmony import */ var _app_app_module__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ./app/app.module */ "./src/app/app.module.ts");
/* harmony import */ var _environments_environment__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ./environments/environment */ "./src/environments/environment.ts");




if (_environments_environment__WEBPACK_IMPORTED_MODULE_3__["environment"].production) {
    Object(_angular_core__WEBPACK_IMPORTED_MODULE_0__["enableProdMode"])();
}
Object(_angular_platform_browser_dynamic__WEBPACK_IMPORTED_MODULE_1__["platformBrowserDynamic"])().bootstrapModule(_app_app_module__WEBPACK_IMPORTED_MODULE_2__["AppModule"])
    .catch(function (err) { return console.error(err); });


/***/ }),

/***/ 0:
/*!***************************!*\
  !*** multi ./src/main.ts ***!
  \***************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

module.exports = __webpack_require__(/*! C:\Users\yveno\Desktop\P6\frontend\src\main.ts */"./src/main.ts");


/***/ })

},[[0,"runtime","vendor"]]]);
//# sourceMappingURL=main.js.map