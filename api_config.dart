// lib/config/api_config.dart
import 'dart:io';
import 'package:flutter/foundation.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'dart:math';
import 'dart:convert';
import 'package:http/http.dart' as http;

class ApiConfig {
  // ===== CORE CONFIGURATION =====
  static const String _baseUrl = 'https://f4761f1b354c.ngrok-free.app';
  static const String _localhostUrl = 'http://localhost:3000';
  static const String _emulatorUrl = 'http://10.0.2.2:3000';
  static const String _iosSimulatorUrl = 'http://127.0.0.1:3000';
  static const String apiVersion = '2.2.0';

  static String _deviceId = '';

  // ===== USER AUTHENTICATION STORAGE =====
  static String? _authToken;
  static String? _refreshToken;
  static DateTime? _tokenExpiry;
  static Map<String, dynamic>? _userInfo;
  static bool _isAuthInitialized = false;

  // User storage keys
  static const String _tokenKey = 'townzy_auth_token';
  static const String _refreshTokenKey = 'townzy_refresh_token';
  static const String _tokenExpiryKey = 'townzy_token_expiry';
  static const String _userInfoKey = 'townzy_user_info';
  static const String _deviceIdKey = 'townzy_device_id';

  // ===== SELLER AUTHENTICATION STORAGE =====
  static String? _sellerAuthToken;
  static String? _sellerRefreshToken;
  static DateTime? _sellerTokenExpiry;
  static Map<String, dynamic>? _sellerInfo;
  static bool _isSellerAuthInitialized = false;

  // Seller storage keys (completely separate from user)
  static const String _sellerTokenKey = 'townzy_seller_token';
  static const String _sellerRefreshTokenKey = 'townzy_seller_refresh_token';
  static const String _sellerTokenExpiryKey = 'townzy_seller_token_expiry';
  static const String _sellerInfoKey = 'townzy_seller_info';

  // ===== USER AUTHENTICATION INITIALIZATION =====
  static Future<void> initializeAuth() async {
    if (_isAuthInitialized) return;

    try {
      final prefs = await SharedPreferences.getInstance();

      // Load stored authentication data
      _authToken = prefs.getString(_tokenKey);
      _refreshToken = prefs.getString(_refreshTokenKey);

      final expiryTimestamp = prefs.getInt(_tokenExpiryKey);
      if (expiryTimestamp != null) {
        _tokenExpiry = DateTime.fromMillisecondsSinceEpoch(expiryTimestamp);
      }

      final userInfoJson = prefs.getString(_userInfoKey);
      if (userInfoJson != null && userInfoJson.isNotEmpty) {
        try {
          _userInfo = json.decode(userInfoJson) as Map<String, dynamic>;
        } catch (e) {
          _userInfo = null;
        }
      }

      // Initialize device ID
      _deviceId = prefs.getString(_deviceIdKey) ?? _generateDeviceId();
      if (!prefs.containsKey(_deviceIdKey)) {
        await prefs.setString(_deviceIdKey, _deviceId);
      }

      _isAuthInitialized = true;
    } catch (e) {
      _isAuthInitialized = true;
    }
  }

  // ===== SELLER AUTHENTICATION INITIALIZATION =====
  static Future<void> initializeSellerAuth() async {
    if (_isSellerAuthInitialized) return;

    try {
      final prefs = await SharedPreferences.getInstance();

      // Load stored seller authentication data
      _sellerAuthToken = prefs.getString(_sellerTokenKey);
      _sellerRefreshToken = prefs.getString(_sellerRefreshTokenKey);

      final sellerExpiryTimestamp = prefs.getInt(_sellerTokenExpiryKey);
      if (sellerExpiryTimestamp != null) {
        _sellerTokenExpiry = DateTime.fromMillisecondsSinceEpoch(sellerExpiryTimestamp);
      }

      final sellerInfoJson = prefs.getString(_sellerInfoKey);
      if (sellerInfoJson != null && sellerInfoJson.isNotEmpty) {
        try {
          _sellerInfo = json.decode(sellerInfoJson) as Map<String, dynamic>;
        } catch (e) {
          _sellerInfo = null;
        }
      }

      _isSellerAuthInitialized = true;
    } catch (e) {
      _isSellerAuthInitialized = true;
    }
  }

  // ===== DEVICE & URL MANAGEMENT =====
  static String get deviceId {
    if (_deviceId.isEmpty) {
      _deviceId = _generateDeviceId();
      _saveDeviceId();
    }
    return _deviceId;
  }

  static void _saveDeviceId() async {
    try {
      final prefs = await SharedPreferences.getInstance();
      await prefs.setString(_deviceIdKey, _deviceId);
    } catch (e) {
      // Handle error silently
    }
  }

  static String _generateDeviceId() {
    final random = Random();
    final timestamp = DateTime.now().millisecondsSinceEpoch;
    final randomSuffix = random.nextInt(9999).toString().padLeft(4, '0');
    return '${Platform.operatingSystem}_${timestamp.toString().substring(8)}_$randomSuffix';
  }

  static String get currentBaseUrl => _baseUrl;

  // ===== USER AUTHENTICATION TOKEN MANAGEMENT =====
  static Future<bool> storeAuthData(Map<String, dynamic> loginResponse) async {
    try {
      if (!_isAuthInitialized) await initializeAuth();

      final prefs = await SharedPreferences.getInstance();

      // Initialize device ID
      _deviceId = prefs.getString(_deviceIdKey) ?? _generateDeviceId();
      if (!prefs.containsKey(_deviceIdKey)) {
        await prefs.setString(_deviceIdKey, _deviceId);
      }

      final token = loginResponse['token'] as String?;
      if (token == null || token.isEmpty) {
        return false;
      }

      final userData = loginResponse['user'] as Map<String, dynamic>?;

      _authToken = token;
      await prefs.setString(_tokenKey, token);

      final expiry = _parseTokenExpiry(token);
      if (expiry != null) {
        _tokenExpiry = expiry;
        await prefs.setInt(_tokenExpiryKey, expiry.millisecondsSinceEpoch);
      }

      if (userData != null) {
        _userInfo = userData;
        await prefs.setString(_userInfoKey, json.encode(userData));
      }

      final refreshToken = loginResponse['refresh_token'] as String?;
      if (refreshToken != null) {
        _refreshToken = refreshToken;
        await prefs.setString(_refreshTokenKey, refreshToken);
      }

      return true;
    } catch (e) {
      return false;
    }
  }

  // ===== SELLER AUTHENTICATION TOKEN MANAGEMENT =====
  static Future<bool> storeSellerAuthData(Map<String, dynamic> loginResponse) async {
    try {
      if (!_isSellerAuthInitialized) await initializeSellerAuth();

      final prefs = await SharedPreferences.getInstance();

      final token = loginResponse['token'] as String?;
      if (token == null || token.isEmpty) {
        return false;
      }

      // Fixed: Access seller data correctly from server response
      final sellerData = loginResponse['seller'] as Map<String, dynamic>?;

      _sellerAuthToken = token;
      await prefs.setString(_sellerTokenKey, token);

      final expiry = _parseTokenExpiry(token);
      if (expiry != null) {
        _sellerTokenExpiry = expiry;
        await prefs.setInt(_sellerTokenExpiryKey, expiry.millisecondsSinceEpoch);
      }

      if (sellerData != null) {
        _sellerInfo = sellerData;
        await prefs.setString(_sellerInfoKey, json.encode(sellerData));
      }

      final refreshToken = loginResponse['refresh_token'] as String?;
      if (refreshToken != null) {
        _sellerRefreshToken = refreshToken;
        await prefs.setString(_sellerRefreshTokenKey, refreshToken);
      }

      return true;
    } catch (e) {
      print('Error storing seller auth data: $e');
      return false;
    }
  }

  static DateTime? _parseTokenExpiry(String token) {
    try {
      final parts = token.split('.');
      if (parts.length != 3) return null;

      String payload = parts[1];
      while (payload.length % 4 != 0) {
        payload += '=';
      }

      final decoded = base64Url.decode(payload);
      final payloadMap = json.decode(utf8.decode(decoded)) as Map<String, dynamic>;

      if (payloadMap.containsKey('exp')) {
        final exp = payloadMap['exp'];
        if (exp is int) {
          return DateTime.fromMillisecondsSinceEpoch(exp * 1000);
        }
      }

      return null;
    } catch (e) {
      return null;
    }
  }

  // ===== USER AUTHENTICATION GETTERS =====
  static String? get authToken {
    if (!isTokenValid) return null;
    return _authToken;
  }

  static bool get isTokenValid {
    if (_authToken == null || _authToken!.isEmpty) return false;
    if (_tokenExpiry == null) return true;
    return DateTime.now().isBefore(_tokenExpiry!);
  }

  static bool get isAuthenticated => isTokenValid;
  static Map<String, dynamic>? get userInfo => _userInfo;

  static String? get userId {
    final id = _userInfo?['id'];
    if (id != null) return id.toString();
    return null;
  }

  static String? get username => _userInfo?['username']?.toString();
  static String? get userEmail => _userInfo?['email']?.toString();

  // ===== SELLER AUTHENTICATION GETTERS =====
  static String? get sellerAuthToken {
    if (!isSellerTokenValid) return null;
    return _sellerAuthToken;
  }

  static bool get isSellerTokenValid {
    if (_sellerAuthToken == null || _sellerAuthToken!.isEmpty) return false;
    if (_sellerTokenExpiry == null) return true;
    return DateTime.now().isBefore(_sellerTokenExpiry!);
  }

  static bool get isSellerAuthenticated => isSellerTokenValid;
  static Map<String, dynamic>? get sellerInfo => _sellerInfo;

  // Fixed: Access seller_id correctly from stored seller data
  static String? get sellerId => _sellerInfo?['seller_id']?.toString();

  static String? get sellerDbId {
    final id = _sellerInfo?['id'];
    if (id != null) return id.toString();
    return null;
  }

  static String? get businessName => _sellerInfo?['business_name']?.toString();
  static String? get shopAddress => _sellerInfo?['shop_address']?.toString();
  static String? get sellerMobile => _sellerInfo?['mobile_number']?.toString();
  static String? get sellerEmail => _sellerInfo?['email']?.toString();

  // ===== CLEAR AUTHENTICATION DATA =====
  static Future<bool> clearAuthData() async {
    try {
      if (!_isAuthInitialized) await initializeAuth();

      final prefs = await SharedPreferences.getInstance();

      _authToken = null;
      _refreshToken = null;
      _tokenExpiry = null;
      _userInfo = null;

      await prefs.remove(_tokenKey);
      await prefs.remove(_refreshTokenKey);
      await prefs.remove(_tokenExpiryKey);
      await prefs.remove(_userInfoKey);

      return true;
    } catch (e) {
      return false;
    }
  }

  static Future<bool> clearSellerAuthData() async {
    try {
      if (!_isSellerAuthInitialized) await initializeSellerAuth();

      final prefs = await SharedPreferences.getInstance();

      _sellerAuthToken = null;
      _sellerRefreshToken = null;
      _sellerTokenExpiry = null;
      _sellerInfo = null;

      await prefs.remove(_sellerTokenKey);
      await prefs.remove(_sellerRefreshTokenKey);
      await prefs.remove(_sellerTokenExpiryKey);
      await prefs.remove(_sellerInfoKey);

      return true;
    } catch (e) {
      return false;
    }
  }

  // ===== AUTHENTICATION ENDPOINTS =====
  static String get loginEndpoint => '$currentBaseUrl/auth/login';
  static String get registerEndpoint => '$currentBaseUrl/auth/register';
  static String get logoutEndpoint => '$currentBaseUrl/auth/logout';
  static String get refreshTokenEndpoint => '$currentBaseUrl/auth/refresh';
  static String get verifyTokenEndpoint => '$currentBaseUrl/auth/verify';
  static String get forgotPasswordEndpoint => '$currentBaseUrl/auth/forgot-password';
  static String get resetPasswordEndpoint => '$currentBaseUrl/auth/reset-password';
  static String get changePasswordEndpoint => '$currentBaseUrl/auth/change-password';

  // Seller endpoints
  static String get sellerLoginEndpoint => '$currentBaseUrl/seller/login';
  static String get sellerRegisterEndpoint => '$currentBaseUrl/seller/register';
  static String get sellerLogoutEndpoint => '$currentBaseUrl/seller/logout';
  static String get sellerRefreshTokenEndpoint => '$currentBaseUrl/seller/refresh';
  static String get sellerCategoriesEndpoint => '$currentBaseUrl/seller/categories';
  static String get sellerAvailableCategoriesEndpoint => '$currentBaseUrl/seller/categories/available';

  // ===== SELLER CATEGORY ENDPOINTS =====
  static String getSellerCategoryEndpoint(int categoryId) {
    _validateId(categoryId, 'Category ID');
    return '$currentBaseUrl/seller/categories/$categoryId';
  }

  static String getSellerCategorySubcategoriesEndpoint(int categoryId) {
    _validateId(categoryId, 'Category ID');
    return '$currentBaseUrl/seller/categories/$categoryId/subcategories';
  }

  static String getDeleteSellerCategoryEndpoint(int categoryId) {
    _validateId(categoryId, 'Category ID');
    return '$currentBaseUrl/seller/categories/$categoryId';
  }

  static String getUpdateSellerCategoryEndpoint(int categoryId) {
    _validateId(categoryId, 'Category ID');
    return '$currentBaseUrl/seller/categories/$categoryId';
  }

  static String getCreateSellerSubcategoryEndpoint(int categoryId) {
    _validateId(categoryId, 'Category ID');
    return '$currentBaseUrl/seller/categories/$categoryId/subcategories';
  }

  // ===== BASIC ENDPOINTS =====
  static String get baseEndpoint => currentBaseUrl;
  static String get testEndpoint => '$currentBaseUrl/test';
  static String get healthEndpoint => '$currentBaseUrl/api/health';
  static String get categoriesEndpoint => '$currentBaseUrl/categories';
  static String get mainCategoriesEndpoint => categoriesEndpoint;
  static String get cardsEndpoint => '$currentBaseUrl/api/cards';
  static String get productsEndpoint => '$currentBaseUrl/api/products';

  // ===== CATEGORY HIERARCHY ENDPOINTS =====
  static String get tailoringCategoryEndpoint => '$currentBaseUrl/categories/1';
  static String get electronicsCategoryEndpoint => '$currentBaseUrl/categories/2';
  static String get homeServicesCategoryEndpoint => '$currentBaseUrl/categories/3';
  static String get beautyWellnessCategoryEndpoint => '$currentBaseUrl/categories/4';
  static String get automotiveCategoryEndpoint => '$currentBaseUrl/categories/5';

  static String get tailoringSubcategoriesEndpoint => '$currentBaseUrl/categories/1/subcategories';
  static String get electronicsSubcategoriesEndpoint => '$currentBaseUrl/categories/2/subcategories';
  static String get homeServicesSubcategoriesEndpoint => '$currentBaseUrl/categories/3/subcategories';
  static String get beautyWellnessSubcategoriesEndpoint => '$currentBaseUrl/categories/4/subcategories';
  static String get automotiveSubcategoriesEndpoint => '$currentBaseUrl/categories/5/subcategories';
  static String get pharmacySubcategoriesEndpoint => '$currentBaseUrl/categories/4/subcategories';

  static String get tailoringSubSubcategoriesEndpoint => '$currentBaseUrl/categories/1/subsubcategories';
  static String get electronicsSubSubcategoriesEndpoint => '$currentBaseUrl/categories/2/subsubcategories';
  static String get homeServicesSubSubcategoriesEndpoint => '$currentBaseUrl/categories/3/subsubcategories';
  static String get beautyWellnessSubSubcategoriesEndpoint => '$currentBaseUrl/categories/4/subsubcategories';
  static String get automotiveSubSubcategoriesEndpoint => '$currentBaseUrl/categories/5/subsubcategories';

  // ===== USER & CONTENT ENDPOINTS =====
  static String get userProfileEndpoint => '$currentBaseUrl/api/user/profile';
  static String get userFavoritesEndpoint => '$currentBaseUrl/api/user/favorites';
  static String get userOrdersEndpoint => '$currentBaseUrl/api/user/orders';
  static String get userSettingsEndpoint => '$currentBaseUrl/api/user/settings';
  static String get servicesEndpoint => '$currentBaseUrl/api/services';
  static String get searchEndpoint => '$currentBaseUrl/api/search';
  static String get reviewsEndpoint => '$currentBaseUrl/api/reviews';
  static String get cartEndpoint => '$currentBaseUrl/api/cart';
  static String get ordersEndpoint => '$currentBaseUrl/api/orders';
  static String get favoritesEndpoint => '$currentBaseUrl/api/user/favorites';
  static String get imageUploadEndpoint => '$currentBaseUrl/api/upload/image';
  static String get userAvatarEndpoint => '$currentBaseUrl/api/user/avatar';

  // ===== DYNAMIC ENDPOINTS =====
  static String getCategoryEndpoint(int categoryId) {
    _validateId(categoryId, 'Category ID');
    return '$currentBaseUrl/categories/$categoryId';
  }

  static String getCategoryDetailsEndpoint(int categoryId) {
    _validateId(categoryId, 'Category ID');
    return '$currentBaseUrl/categories/$categoryId/details';
  }

  static String getSubcategoriesEndpoint(int categoryId) {
    _validateId(categoryId, 'Category ID');
    return '$currentBaseUrl/categories/$categoryId/subcategories';
  }

  static String getSubSubcategoriesEndpoint(int categoryId) {
    _validateId(categoryId, 'Category ID');
    return '$currentBaseUrl/categories/$categoryId/subsubcategories';
  }

  static String getSubcategorySubSubcategoriesEndpoint(int categoryId, int subcategoryId) {
    _validateId(categoryId, 'Category ID');
    _validateId(subcategoryId, 'Subcategory ID');
    return '$currentBaseUrl/categories/$categoryId/subcategories/$subcategoryId/subsubcategories';
  }

  static String getProductsByCategoryEndpoint(int categoryId) {
    _validateId(categoryId, 'Category ID');
    return '$currentBaseUrl/api/categories/$categoryId/products';
  }

  static String getServicesByCategoryEndpoint(int categoryId) {
    _validateId(categoryId, 'Category ID');
    return '$currentBaseUrl/categories/$categoryId/services';
  }

  static String getItemDetailsEndpoint(String itemId, {String type = 'products'}) {
    _validateStringId(itemId, 'Item ID');
    return '$currentBaseUrl/api/$type/$itemId';
  }

  static String getUserItemsEndpoint(String userId, String itemType) {
    _validateStringId(userId, 'User ID');
    return '$currentBaseUrl/api/users/$userId/$itemType';
  }

  // ===== IMAGE URLS =====
  static String getUserAvatarUrl(String userId) {
    _validateStringId(userId, 'User ID');
    return '$currentBaseUrl/images/users/$userId/avatar.jpg';
  }

  static String getCategoryImageUrl(int categoryId) {
    _validateId(categoryId, 'Category ID');
    return '$currentBaseUrl/images/categories/$categoryId.jpg';
  }

  static String getSubcategoryImageUrl(int subcategoryId) {
    _validateId(subcategoryId, 'Subcategory ID');
    return '$currentBaseUrl/images/subcategories/$subcategoryId.jpg';
  }

  static String getSubSubcategoryImageUrl(int subSubcategoryId) {
    _validateId(subSubcategoryId, 'Sub-subcategory ID');
    return '$currentBaseUrl/images/subsubcategories/$subSubcategoryId.jpg';
  }

  static String getProductImageUrl(String productId) {
    _validateStringId(productId, 'Product ID');
    return '$currentBaseUrl/images/products/$productId.jpg';
  }

  // ===== ADMIN ENDPOINTS =====
  static String get addCategoryEndpoint => '$currentBaseUrl/categories';

  static String getAddSubcategoryEndpoint(int categoryId) {
    _validateId(categoryId, 'Category ID');
    return '$currentBaseUrl/categories/$categoryId/subcategories';
  }

  static String getAddSubSubcategoryEndpoint(int categoryId, int subcategoryId) {
    _validateId(categoryId, 'Category ID');
    _validateId(subcategoryId, 'Subcategory ID');
    return '$currentBaseUrl/categories/$categoryId/subcategories/$subcategoryId/subsubcategories';
  }

  static String getUpdateCategoryEndpoint(int categoryId) {
    _validateId(categoryId, 'Category ID');
    return '$currentBaseUrl/categories/$categoryId';
  }

  static String getDeleteCategoryEndpoint(int categoryId) {
    _validateId(categoryId, 'Category ID');
    return '$currentBaseUrl/categories/$categoryId';
  }

  // ===== SEARCH & FILTER ENDPOINTS =====
  static String getSearchEndpoint(String query) {
    if (query.isEmpty) throw ArgumentError('Search query cannot be empty');
    return '$currentBaseUrl/api/search?q=${Uri.encodeComponent(query)}';
  }

  static String getAdvancedSearchEndpoint({
    String? query,
    int? categoryId,
    List<int>? subcategoryIds,
    List<int>? subSubcategoryIds,
    double? minPrice,
    double? maxPrice,
    double? minRating,
    String? location,
    String? sortBy,
    String? sortOrder,
    int? page,
    int? limit,
  }) {
    final params = <String>[];

    if (query?.isNotEmpty == true) params.add('q=${Uri.encodeComponent(query!)}');
    if (categoryId != null && categoryId > 0) params.add('category_id=$categoryId');
    if (subcategoryIds?.isNotEmpty == true) params.add('subcategory_ids=${subcategoryIds!.join(',')}');
    if (subSubcategoryIds?.isNotEmpty == true) params.add('subsubcategory_ids=${subSubcategoryIds!.join(',')}');
    if (minPrice != null && minPrice >= 0) params.add('min_price=$minPrice');
    if (maxPrice != null && maxPrice >= 0) params.add('max_price=$maxPrice');
    if (minRating != null && minRating >= 0 && minRating <= 5) params.add('min_rating=$minRating');
    if (location?.isNotEmpty == true) params.add('location=${Uri.encodeComponent(location!)}');
    if (sortBy?.isNotEmpty == true) params.add('sort_by=${Uri.encodeComponent(sortBy!)}');
    if (sortOrder == 'asc' || sortOrder == 'desc') params.add('sort_order=$sortOrder');
    if (page != null && page > 0) params.add('page=$page');
    if (limit != null && limit > 0 && limit <= maxPageSize) params.add('limit=$limit');

    final queryString = params.isNotEmpty ? '?${params.join('&')}' : '';
    return '$currentBaseUrl/api/search$queryString';
  }

  static String getNearbyEndpoint({
    required double latitude,
    required double longitude,
    double? radiusKm,
    int? categoryId,
    int? limit,
  }) {
    if (latitude < -90 || latitude > 90) throw ArgumentError('Invalid latitude: $latitude');
    if (longitude < -180 || longitude > 180) throw ArgumentError('Invalid longitude: $longitude');

    final params = <String>[
      'lat=$latitude',
      'lng=$longitude',
    ];

    if (radiusKm != null && radiusKm > 0) params.add('radius=$radiusKm');
    if (categoryId != null && categoryId > 0) params.add('category_id=$categoryId');
    if (limit != null && limit > 0) params.add('limit=$limit');

    return '$currentBaseUrl/api/nearby?${params.join('&')}';
  }

  // ===== HTTP HEADERS & SECURITY =====
  static Map<String, String> get headers => {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
    'User-Agent': 'Townzy-Flutter-App/$apiVersion ($deviceId)',
    'X-API-Version': apiVersion,
    'X-Device-ID': deviceId,
    'X-Platform': Platform.operatingSystem,
    'X-App-Version': apiVersion,
    'ngrok-skip-browser-warning': 'true',
  };

  static Map<String, String> get authHeaders {
    final Map<String, String> baseHeaders = Map.from(headers);
    if (isAuthenticated && _authToken != null) {
      baseHeaders['Authorization'] = 'Bearer $_authToken';
    }
    return baseHeaders;
  }

  static Map<String, String> get sellerAuthHeaders {
    final Map<String, String> baseHeaders = Map.from(headers);
    if (isSellerAuthenticated && _sellerAuthToken != null) {
      baseHeaders['Authorization'] = 'Bearer $_sellerAuthToken';
    }
    return baseHeaders;
  }

  static Map<String, String> getAuthHeaders(String token) {
    if (token.isEmpty) throw ArgumentError('Token cannot be empty');
    return {...headers, 'Authorization': 'Bearer $token'};
  }

  static Map<String, String> get formHeaders => {
    'Content-Type': 'application/x-www-form-urlencoded',
    'Accept': 'application/json',
    'User-Agent': 'Townzy-Flutter-App/$apiVersion ($deviceId)',
    'X-API-Version': apiVersion,
    'X-Device-ID': deviceId,
    'X-Platform': Platform.operatingSystem,
    'ngrok-skip-browser-warning': 'true',
  };

  static Map<String, String> getMultipartHeaders([String? token]) {
    final baseHeaders = {
      'Accept': 'application/json',
      'User-Agent': 'Townzy-Flutter-App/$apiVersion ($deviceId)',
      'X-API-Version': apiVersion,
      'X-Device-ID': deviceId,
      'X-Platform': Platform.operatingSystem,
      'ngrok-skip-browser-warning': 'true',
    };

    final authToken = token ?? _authToken;
    if (authToken?.isNotEmpty == true) {
      baseHeaders['Authorization'] = 'Bearer $authToken';
    }

    return baseHeaders;
  }

  static Map<String, String> getSellerMultipartHeaders([String? token]) {
    final baseHeaders = {
      'Accept': 'application/json',
      'User-Agent': 'Townzy-Flutter-App/$apiVersion ($deviceId)',
      'X-API-Version': apiVersion,
      'X-Device-ID': deviceId,
      'X-Platform': Platform.operatingSystem,
      'ngrok-skip-browser-warning': 'true',
    };

    final sellerToken = token ?? _sellerAuthToken;
    if (sellerToken?.isNotEmpty == true) {
      baseHeaders['Authorization'] = 'Bearer $sellerToken';
    }

    return baseHeaders;
  }

  // ===== USER AUTHENTICATION HELPERS =====
  static Map<String, dynamic> createLoginData({
    String? email,
    String? username,
    required String password,
  }) {
    final data = <String, dynamic>{
      'password': password,
      'device_id': deviceId,
      'platform': Platform.operatingSystem,
    };

    if (email != null && email.isNotEmpty) {
      data['email'] = email;
    } else if (username != null && username.isNotEmpty) {
      data['username'] = username;
    } else {
      throw ArgumentError('Either email or username must be provided');
    }

    return data;
  }

  static Map<String, dynamic> createRegistrationData({
    required String email,
    required String password,
    String? username,
    String? firstName,
    String? lastName,
    String? phone,
  }) {
    return {
      'email': email,
      'password': password,
      'username': username ?? email.split('@')[0],
      'first_name': firstName ?? '',
      'last_name': lastName ?? '',
      'phone': phone ?? '',
      'device_id': deviceId,
      'platform': Platform.operatingSystem,
    };
  }

  static Future<bool> handleLoginSuccess(Map<String, dynamic> response) async {
    try {
      if (!_isAuthInitialized) await initializeAuth();
      final success = await storeAuthData(response);
      return success;
    } catch (e) {
      return false;
    }
  }

  static Future<bool> logout() async {
    try {
      final success = await clearAuthData();
      return success;
    } catch (e) {
      return false;
    }
  }

  // ===== SELLER AUTHENTICATION HELPERS =====
  static Map<String, dynamic> createSellerLoginData({
    String? sellerId,
    String? mobileNumber,
    required String password,
  }) {
    final data = <String, dynamic>{
      'password': password,
      'device_id': deviceId,
      'platform': Platform.operatingSystem,
    };

    if (sellerId != null && sellerId.isNotEmpty) {
      data['seller_id'] = sellerId;
    } else if (mobileNumber != null && mobileNumber.isNotEmpty) {
      data['mobile_number'] = mobileNumber;
    } else {
      throw ArgumentError('Either seller_id or mobile_number must be provided');
    }

    return data;
  }

  static Map<String, dynamic> createSellerRegistrationData({
    required String businessName,
    required String shopAddress,
    required String mobileNumber,
    required String password,
    String? email,
  }) {
    return {
      'business_name': businessName,
      'shop_address': shopAddress,
      'mobile_number': mobileNumber,
      'password': password,
      'email': email,
      'device_id': deviceId,
      'platform': Platform.operatingSystem,
    };
  }

  static Future<bool> handleSellerLoginSuccess(Map<String, dynamic> response) async {
    try {
      if (!_isSellerAuthInitialized) await initializeSellerAuth();
      final success = await storeSellerAuthData(response);
      return success;
    } catch (e) {
      return false;
    }
  }

  static Future<bool> logoutSeller() async {
    try {
      final success = await clearSellerAuthData();
      return success;
    } catch (e) {
      return false;
    }
  }

  // ===== SELLER CATEGORY MANAGEMENT HELPERS =====
  static Map<String, dynamic> createSellerCategoryData({
    required String name,
    String? description,
    String? color,
    String? icon,
    int? parentId,
    int? sortOrder,
  }) {
    return {
      'name': name,
      'description': description ?? '',
      'color': color ?? '#2196F3',
      'icon': icon ?? 'category',
      'parent_id': parentId,
      'sort_order': sortOrder ?? 0,
    };
  }

  static Map<String, dynamic> createSellerSubcategoryData({
    required String name,
    String? description,
    String? color,
    String? icon,
    int? sortOrder,
  }) {
    return {
      'name': name,
      'description': description ?? '',
      'color': color ?? '#2196F3',
      'icon': icon ?? 'category',
      'sort_order': sortOrder ?? 0,
    };
  }

  static Map<String, dynamic> createSellerCategoryUpdateData({
    String? name,
    String? description,
    String? color,
    String? icon,
    int? parentId,
    int? sortOrder,
  }) {
    final data = <String, dynamic>{};
    if (name != null) data['name'] = name;
    if (description != null) data['description'] = description;
    if (color != null) data['color'] = color;
    if (icon != null) data['icon'] = icon;
    if (parentId != null) data['parent_id'] = parentId;
    if (sortOrder != null) data['sort_order'] = sortOrder;
    return data;
  }

  // ===== API METHODS - USER AUTHENTICATION =====
  static Future<ApiResponse<Map<String, dynamic>>> userLogin({
    String? email,
    String? username,
    required String password,
  }) async {
    try {
      await initializeAuth();

      final loginData = createLoginData(
        email: email,
        username: username,
        password: password,
      );

      final response = await http.post(
        Uri.parse(loginEndpoint),
        headers: headers,
        body: json.encode(loginData),
      );

      final data = json.decode(response.body) as Map<String, dynamic>;

      if (response.statusCode == 200) {
        await handleLoginSuccess(data);
        return ApiResponse.success(data, 'Login successful');
      } else {
        return ApiResponse.error(getErrorFromResponse(data), response.statusCode);
      }
    } catch (e) {
      return ApiResponse.error('Login failed: $e');
    }
  }

  static Future<ApiResponse<Map<String, dynamic>>> userRegister({
    required String email,
    required String password,
    String? username,
    String? firstName,
    String? lastName,
    String? phone,
  }) async {
    try {
      await initializeAuth();

      final registrationData = createRegistrationData(
        email: email,
        password: password,
        username: username,
        firstName: firstName,
        lastName: lastName,
        phone: phone,
      );

      final response = await http.post(
        Uri.parse(registerEndpoint),
        headers: headers,
        body: json.encode(registrationData),
      );

      final data = json.decode(response.body) as Map<String, dynamic>;

      if (response.statusCode == 201) {
        await handleLoginSuccess(data);
        return ApiResponse.success(data, 'Registration successful');
      } else {
        return ApiResponse.error(getErrorFromResponse(data), response.statusCode);
      }
    } catch (e) {
      return ApiResponse.error('Registration failed: $e');
    }
  }

  static Future<ApiResponse<Map<String, dynamic>>> sellerLogin({
    String? sellerId,
    String? mobileNumber,
    required String password,
  }) async {
    try {
      await initializeSellerAuth();

      final loginData = createSellerLoginData(
        sellerId: sellerId,
        mobileNumber: mobileNumber,
        password: password,
      );

      final response = await http.post(
        Uri.parse(sellerLoginEndpoint),
        headers: headers,
        body: json.encode(loginData),
      );

      final data = json.decode(response.body) as Map<String, dynamic>;

      if (response.statusCode == 200) {
        await handleSellerLoginSuccess(data);
        return ApiResponse.success(data, 'Seller login successful');
      } else {
        return ApiResponse.error(getErrorFromResponse(data), response.statusCode);
      }
    } catch (e) {
      return ApiResponse.error('Seller login failed: $e');
    }
  }

  static Future<ApiResponse<Map<String, dynamic>>> sellerRegister({
    required String businessName,
    required String shopAddress,
    required String mobileNumber,
    required String password,
    String? email,
  }) async {
    try {
      await initializeSellerAuth();

      final registrationData = createSellerRegistrationData(
        businessName: businessName,
        shopAddress: shopAddress,
        mobileNumber: mobileNumber,
        password: password,
        email: email,
      );

      final response = await http.post(
        Uri.parse(sellerRegisterEndpoint),
        headers: headers,
        body: json.encode(registrationData),
      );

      final data = json.decode(response.body) as Map<String, dynamic>;

      if (response.statusCode == 201) {
        await handleSellerLoginSuccess(data);
        return ApiResponse.success(data, 'Seller registration successful');
      } else {
        return ApiResponse.error(getErrorFromResponse(data), response.statusCode);
      }
    } catch (e) {
      return ApiResponse.error('Seller registration failed: $e');
    }
  }

  // ===== API METHODS - SELLER CATEGORY MANAGEMENT =====
  static Future<ApiResponse<List<Map<String, dynamic>>>> getSellerCategories() async {
    try {
      await initializeSellerAuth();

      if (!isSellerAuthenticated) {
        return ApiResponse.error('Seller not authenticated', 401);
      }

      final response = await http.get(
        Uri.parse(sellerCategoriesEndpoint),
        headers: sellerAuthHeaders,
      );

      final data = json.decode(response.body) as Map<String, dynamic>;

      if (response.statusCode == 200) {
        final categories = data['data'] as List? ?? [];
        return ApiResponse.success(
            List<Map<String, dynamic>>.from(categories),
            'Seller categories retrieved successfully'
        );
      } else {
        return ApiResponse.error(getErrorFromResponse(data), response.statusCode);
      }
    } catch (e) {
      return ApiResponse.error('Failed to get seller categories: $e');
    }
  }

  static Future<ApiResponse<Map<String, dynamic>>> createSellerCategory({
    required String name,
    String? description,
    String? color,
    String? icon,
    int? parentId,
    int? sortOrder,
  }) async {
    try {
      await initializeSellerAuth();

      if (!isSellerAuthenticated) {
        return ApiResponse.error('Seller not authenticated', 401);
      }

      final categoryData = createSellerCategoryData(
        name: name,
        description: description,
        color: color,
        icon: icon,
        parentId: parentId,
        sortOrder: sortOrder,
      );

      final response = await http.post(
        Uri.parse(sellerCategoriesEndpoint),
        headers: sellerAuthHeaders,
        body: json.encode(categoryData),
      );

      final data = json.decode(response.body) as Map<String, dynamic>;

      if (response.statusCode == 201) {
        return ApiResponse.success(data, 'Category created successfully');
      } else {
        return ApiResponse.error(getErrorFromResponse(data), response.statusCode);
      }
    } catch (e) {
      return ApiResponse.error('Failed to create seller category: $e');
    }
  }

  static Future<ApiResponse<Map<String, dynamic>>> updateSellerCategory({
    required int categoryId,
    String? name,
    String? description,
    String? color,
    String? icon,
    int? parentId,
    int? sortOrder,
  }) async {
    try {
      await initializeSellerAuth();

      if (!isSellerAuthenticated) {
        return ApiResponse.error('Seller not authenticated', 401);
      }

      final updateData = createSellerCategoryUpdateData(
        name: name,
        description: description,
        color: color,
        icon: icon,
        parentId: parentId,
        sortOrder: sortOrder,
      );

      final response = await http.put(
        Uri.parse(getUpdateSellerCategoryEndpoint(categoryId)),
        headers: sellerAuthHeaders,
        body: json.encode(updateData),
      );

      final data = json.decode(response.body) as Map<String, dynamic>;

      if (response.statusCode == 200) {
        return ApiResponse.success(data, 'Category updated successfully');
      } else {
        return ApiResponse.error(getErrorFromResponse(data), response.statusCode);
      }
    } catch (e) {
      return ApiResponse.error('Failed to update seller category: $e');
    }
  }

  static Future<ApiResponse<Map<String, dynamic>>> deleteSellerCategory(int categoryId) async {
    try {
      await initializeSellerAuth();

      if (!isSellerAuthenticated) {
        return ApiResponse.error('Seller not authenticated', 401);
      }

      final response = await http.delete(
        Uri.parse(getDeleteSellerCategoryEndpoint(categoryId)),
        headers: sellerAuthHeaders,
      );

      final data = json.decode(response.body) as Map<String, dynamic>;

      if (response.statusCode == 200) {
        return ApiResponse.success(data, 'Sub-subcategory deleted successfully');
      } else {
        return ApiResponse.error(getErrorFromResponse(data), response.statusCode);
      }
    } catch (e) {
      return ApiResponse.error('Failed to delete seller category: $e');
    }
  }

  static Future<ApiResponse<List<Map<String, dynamic>>>> getSellerCategorySubcategories(int categoryId) async {
    try {
      await initializeSellerAuth();

      if (!isSellerAuthenticated) {
        return ApiResponse.error('Seller not authenticated', 401);
      }

      final response = await http.get(
        Uri.parse(getSellerCategorySubcategoriesEndpoint(categoryId)),
        headers: sellerAuthHeaders,
      );

      final data = json.decode(response.body) as Map<String, dynamic>;

      if (response.statusCode == 200) {
        final subcategories = data['data'] as List? ?? [];
        return ApiResponse.success(
            List<Map<String, dynamic>>.from(subcategories),
            'Seller subcategories retrieved successfully'
        );
      } else {
        return ApiResponse.error(getErrorFromResponse(data), response.statusCode);
      }
    } catch (e) {
      return ApiResponse.error('Failed to get seller subcategories: $e');
    }
  }

  static Future<ApiResponse<Map<String, dynamic>>> createSellerSubcategory({
    required int categoryId,
    required String name,
    String? description,
    String? color,
    String? icon,
    int? sortOrder,
  }) async {
    try {
      await initializeSellerAuth();

      if (!isSellerAuthenticated) {
        return ApiResponse.error('Seller not authenticated', 401);
      }

      final subcategoryData = createSellerSubcategoryData(
        name: name,
        description: description,
        color: color,
        icon: icon,
        sortOrder: sortOrder,
      );

      final response = await http.post(
        Uri.parse(getCreateSellerSubcategoryEndpoint(categoryId)),
        headers: sellerAuthHeaders,
        body: json.encode(subcategoryData),
      );

      final data = json.decode(response.body) as Map<String, dynamic>;

      if (response.statusCode == 201) {
        return ApiResponse.success(data, 'Subcategory created successfully');
      } else {
        return ApiResponse.error(getErrorFromResponse(data), response.statusCode);
      }
    } catch (e) {
      return ApiResponse.error('Failed to create seller subcategory: $e');
    }
  }

  static Future<ApiResponse<List<Map<String, dynamic>>>> getAvailableCategories() async {
    try {
      await initializeSellerAuth();

      if (!isSellerAuthenticated) {
        return ApiResponse.error('Seller not authenticated', 401);
      }

      final response = await http.get(
        Uri.parse(sellerAvailableCategoriesEndpoint),
        headers: sellerAuthHeaders,
      );

      final data = json.decode(response.body) as Map<String, dynamic>;

      if (response.statusCode == 200) {
        final categories = data['data'] as List? ?? [];
        return ApiResponse.success(
            List<Map<String, dynamic>>.from(categories),
            'Available categories retrieved successfully'
        );
      } else {
        return ApiResponse.error(getErrorFromResponse(data), response.statusCode);
      }
    } catch (e) {
      return ApiResponse.error('Failed to get available categories: $e');
    }
  }

  // ===== API METHODS - PUBLIC ENDPOINTS =====
  static Future<ApiResponse<List<Map<String, dynamic>>>> getCategories() async {
    try {
      final response = await http.get(
        Uri.parse(categoriesEndpoint),
        headers: headers,
      );

      final data = json.decode(response.body) as Map<String, dynamic>;

      if (response.statusCode == 200) {
        final categories = data['data'] as List? ?? [];
        return ApiResponse.success(
            List<Map<String, dynamic>>.from(categories),
            'Categories retrieved successfully'
        );
      } else {
        return ApiResponse.error(getErrorFromResponse(data), response.statusCode);
      }
    } catch (e) {
      return ApiResponse.error('Failed to get categories: $e');
    }
  }

  static Future<ApiResponse<List<Map<String, dynamic>>>> getCategoryData(int categoryId) async {
    try {
      final response = await http.get(
        Uri.parse(getCategoryEndpoint(categoryId)),
        headers: headers,
      );

      final data = json.decode(response.body) as Map<String, dynamic>;

      if (response.statusCode == 200) {
        final categoryData = data['data'] as List? ?? [];
        return ApiResponse.success(
            List<Map<String, dynamic>>.from(categoryData),
            'Category data retrieved successfully'
        );
      } else {
        return ApiResponse.error(getErrorFromResponse(data), response.statusCode);
      }
    } catch (e) {
      return ApiResponse.error('Failed to get category data: $e');
    }
  }

  static Future<ApiResponse<List<Map<String, dynamic>>>> getSubcategories(int categoryId) async {
    try {
      final response = await http.get(
        Uri.parse(getSubcategoriesEndpoint(categoryId)),
        headers: headers,
      );

      final data = json.decode(response.body) as Map<String, dynamic>;

      if (response.statusCode == 200) {
        final subcategories = data['data'] as List? ?? [];
        return ApiResponse.success(
            List<Map<String, dynamic>>.from(subcategories),
            'Subcategories retrieved successfully'
        );
      } else {
        return ApiResponse.error(getErrorFromResponse(data), response.statusCode);
      }
    } catch (e) {
      return ApiResponse.error('Failed to get subcategories: $e');
    }
  }

  static Future<ApiResponse<Map<String, dynamic>>> testConnection() async {
    try {
      final response = await http.get(
        Uri.parse(testEndpoint),
        headers: headers,
      );

      final data = json.decode(response.body) as Map<String, dynamic>;

      if (response.statusCode == 200) {
        return ApiResponse.success(data, 'Connection test successful');
      } else {
        return ApiResponse.error(getErrorFromResponse(data), response.statusCode);
      }
    } catch (e) {
      return ApiResponse.error('Connection test failed: $e');
    }
  }

  static Future<ApiResponse<Map<String, dynamic>>> healthCheck() async {
    try {
      final response = await http.get(
        Uri.parse(healthEndpoint),
        headers: headers,
      );

      final data = json.decode(response.body) as Map<String, dynamic>;

      if (response.statusCode == 200) {
        return ApiResponse.success(data, 'Health check successful');
      } else {
        return ApiResponse.error(getErrorFromResponse(data), response.statusCode);
      }
    } catch (e) {
      return ApiResponse.error('Health check failed: $e');
    }
  }

  // ===== DATA PARSING HELPERS =====
  static List<Map<String, dynamic>>? extractSubcategoriesFromResponse(dynamic response) {
    try {
      if (response is List) return List<Map<String, dynamic>>.from(response);

      if (response is Map<String, dynamic>) {
        if (response.containsKey('category') && response['category'] is Map) {
          final category = response['category'] as Map<String, dynamic>;
          if (category.containsKey('subcategories') && category['subcategories'] is List) {
            return List<Map<String, dynamic>>.from(category['subcategories'] as List);
          }
        }

        if (response.containsKey('data') && response['data'] is List) {
          return List<Map<String, dynamic>>.from(response['data'] as List);
        }

        if (response.containsKey('subcategories') && response['subcategories'] is List) {
          return List<Map<String, dynamic>>.from(response['subcategories'] as List);
        }
      }

      return null;
    } catch (e) {
      return null;
    }
  }

  static List<Map<String, dynamic>>? extractSubSubcategoriesFromResponse(dynamic response) {
    try {
      if (response is List) return List<Map<String, dynamic>>.from(response);

      if (response is Map<String, dynamic>) {
        if (response.containsKey('subcategory') && response['subcategory'] is Map) {
          final subcategory = response['subcategory'] as Map<String, dynamic>;
          if (subcategory.containsKey('subsubcategories') && subcategory['subsubcategories'] is List) {
            return List<Map<String, dynamic>>.from(subcategory['subsubcategories'] as List);
          }
        }

        if (response.containsKey('data') && response['data'] is List) {
          return List<Map<String, dynamic>>.from(response['data'] as List);
        }

        if (response.containsKey('subsubcategories') && response['subsubcategories'] is List) {
          return List<Map<String, dynamic>>.from(response['subsubcategories'] as List);
        }
      }

      return null;
    } catch (e) {
      return null;
    }
  }

  static bool hasNoSubcategories(dynamic response) {
    try {
      final subcategories = extractSubcategoriesFromResponse(response);
      return subcategories == null || subcategories.isEmpty;
    } catch (e) {
      return true;
    }
  }

  static bool hasNoSubSubcategories(dynamic response) {
    try {
      final subSubcategories = extractSubSubcategoriesFromResponse(response);
      return subSubcategories == null || subSubcategories.isEmpty;
    } catch (e) {
      return true;
    }
  }

  static int getSubcategoryCount(dynamic response) {
    try {
      if (response is Map<String, dynamic>) {
        if (response.containsKey('total_count') && response['total_count'] is int) {
          return response['total_count'] as int;
        }
        if (response.containsKey('total_subcategories') && response['total_subcategories'] is int) {
          return response['total_subcategories'] as int;
        }
        if (response.containsKey('count') && response['count'] is int) {
          return response['count'] as int;
        }
      }

      final subcategories = extractSubcategoriesFromResponse(response);
      return subcategories?.length ?? 0;
    } catch (e) {
      return 0;
    }
  }

  static int getSubSubcategoryCount(dynamic response) {
    try {
      if (response is Map<String, dynamic>) {
        if (response.containsKey('total_subsubcategories') && response['total_subsubcategories'] is int) {
          return response['total_subsubcategories'] as int;
        }
        if (response.containsKey('count') && response['count'] is int) {
          return response['count'] as int;
        }
      }

      final subSubcategories = extractSubSubcategoriesFromResponse(response);
      return subSubcategories?.length ?? 0;
    } catch (e) {
      return 0;
    }
  }

  // ===== ERROR HANDLING HELPERS =====
  static String getErrorFromResponse(dynamic response) {
    if (response is Map<String, dynamic>) {
      if (response.containsKey('error')) {
        return response['error'].toString();
      }
      if (response.containsKey('message')) {
        return response['message'].toString();
      }
    }
    return 'Unknown error occurred';
  }

  static bool isSuccessResponse(dynamic response) {
    if (response is Map<String, dynamic>) {
      return response.containsKey('success') ? response['success'] == true : true;
    }
    return true;
  }

  // ===== ADMIN DATA HELPERS =====
  static Future<Map<String, dynamic>> addCategory({
    required String name,
    String? description,
    String? color,
    String? icon,
    int? sortOrder,
  }) async {
    return {
      'name': name,
      'description': description ?? '',
      'color': color ?? '#2196F3',
      'icon': icon ?? 'category',
      'sort_order': sortOrder ?? 0,
    };
  }

  static Future<Map<String, dynamic>> addSubcategory({
    required int parentId,
    required String name,
    String? description,
    String? color,
    String? icon,
    int? sortOrder,
  }) async {
    return {
      'name': name,
      'description': description ?? '',
      'color': color,
      'icon': icon ?? 'category',
      'sort_order': sortOrder ?? 0,
    };
  }

  static Future<Map<String, dynamic>> addSubSubcategory({
    required int categoryId,
    required int subcategoryId,
    required String name,
    String? description,
    String? color,
    String? icon,
    int? sortOrder,
  }) async {
    return {
      'name': name,
      'description': description ?? '',
      'color': color,
      'icon': icon ?? 'category',
      'sort_order': sortOrder ?? 0,
      'category_id': categoryId,
      'subcategory_id': subcategoryId,
    };
  }

  static Future<Map<String, dynamic>> updateCategoryData({
    String? name,
    String? description,
    String? color,
    String? icon,
    int? sortOrder,
    bool? isActive,
  }) async {
    final data = <String, dynamic>{};
    if (name != null) data['name'] = name;
    if (description != null) data['description'] = description;
    if (color != null) data['color'] = color;
    if (icon != null) data['icon'] = icon;
    if (sortOrder != null) data['sort_order'] = sortOrder;
    if (isActive != null) data['is_active'] = isActive;
    return data;
  }

  // ===== CONSTANTS =====
  static const Duration connectionTimeout = Duration(seconds: 30);
  static const Duration receiveTimeout = Duration(seconds: 45);
  static const Duration sendTimeout = Duration(seconds: 30);
  static const int maxRetries = 3;
  static const Duration retryDelay = Duration(seconds: 2);
  static const List<int> retryStatusCodes = [500, 502, 503, 504];
  static const Duration cacheValidityDuration = Duration(minutes: 15);
  static const Duration imageCacheValidityDuration = Duration(hours: 24);
  static const int maxCacheSize = 50;
  static const int maxImageSize = 10 * 1024 * 1024;
  static const int maxImageWidth = 2048;
  static const int maxImageHeight = 2048;
  static const List<String> supportedImageTypes = ['jpg', 'jpeg', 'png', 'gif', 'webp'];
  static const int imageQuality = 85;
  static const int defaultPageSize = 20;
  static const int maxPageSize = 100;
  static const int minPageSize = 1;
  static const int minSearchLength = 2;
  static const int maxSearchLength = 100;
  static const Duration searchDebounceTime = Duration(milliseconds: 500);
  static const double defaultSearchRadius = 10.0;
  static const double maxSearchRadius = 100.0;
  static const double minSearchRadius = 0.5;

  // HTTP Status Codes
  static const int successCode = 200;
  static const int createdCode = 201;
  static const int noContentCode = 204;
  static const int badRequestCode = 400;
  static const int unauthorizedCode = 401;
  static const int forbiddenCode = 403;
  static const int notFoundCode = 404;
  static const int conflictCode = 409;
  static const int rateLimitCode = 429;
  static const int serverErrorCode = 500;
  static const int serviceUnavailableCode = 503;

  // ===== UTILITY METHODS =====
  static void _validateId(int id, String fieldName) {
    if (id <= 0) throw ArgumentError('$fieldName must be a positive integer, got: $id');
  }

  static void _validateStringId(String id, String fieldName) {
    if (id.isEmpty) throw ArgumentError('$fieldName cannot be empty');
  }

  static bool isValidUrl(String url) {
    try {
      final uri = Uri.parse(url);
      return uri.hasAbsolutePath && uri.hasScheme && (uri.scheme == 'http' || uri.scheme == 'https');
    } catch (e) {
      return false;
    }
  }

  static String validateServerUrl(String url) {
    if (!isValidUrl(url)) throw ArgumentError('Invalid server URL: $url');
    return url;
  }

  static bool isSuccessStatusCode(int statusCode) => statusCode >= 200 && statusCode < 300;
  static bool isRetryableError(int statusCode) => retryStatusCodes.contains(statusCode);

  static String getErrorMessage(int statusCode) {
    switch (statusCode) {
      case badRequestCode: return 'Bad request. Please check your input.';
      case unauthorizedCode: return 'Unauthorized. Please log in again.';
      case forbiddenCode: return 'Access denied. You don\'t have permission.';
      case notFoundCode: return 'Resource not found.';
      case conflictCode: return 'Conflict. Resource already exists.';
      case rateLimitCode: return 'Too many requests from this device. Please try again later.';
      case serverErrorCode: return 'Server error. Please try again later.';
      case serviceUnavailableCode: return 'Service temporarily unavailable.';
      default: return 'Network error. Please check your connection.';
    }
  }

  static String buildQueryParams(Map<String, dynamic> params) {
    if (params.isEmpty) return '';
    final List<String> queryParts = [];
    params.forEach((key, value) {
      if (value != null) {
        queryParts.add('${Uri.encodeComponent(key)}=${Uri.encodeComponent(value.toString())}');
      }
    });
    return queryParts.isNotEmpty ? '?${queryParts.join('&')}' : '';
  }
}

// ===== API RESPONSE CLASS =====
class ApiResponse<T> {
  final bool isSuccess;
  final T? data;
  final String message;
  final int? statusCode;
  final String? error;

  ApiResponse._({
    required this.isSuccess,
    this.data,
    required this.message,
    this.statusCode,
    this.error,
  });

  factory ApiResponse.success(T data, String message, [int? statusCode]) {
    return ApiResponse._(
      isSuccess: true,
      data: data,
      message: message,
      statusCode: statusCode ?? 200,
    );
  }

  factory ApiResponse.error(String error, [int? statusCode]) {
    return ApiResponse._(
      isSuccess: false,
      message: error,
      statusCode: statusCode ?? 500,
      error: error,
    );
  }

  bool get isError => !isSuccess;

  @override
  String toString() {
    if (isSuccess) {
      return 'ApiResponse.success(message: $message, statusCode: $statusCode)';
    } else {
      return 'ApiResponse.error(error: $error, statusCode: $statusCode)';
    }
  }
}