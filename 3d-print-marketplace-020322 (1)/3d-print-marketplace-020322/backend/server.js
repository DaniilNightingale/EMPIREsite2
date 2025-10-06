const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');
const winston = require('winston');
const helmet = require('helmet');
const bcrypt = require('bcrypt');
require('dotenv').config();

const app = express();


// 日志配置
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.printf(({ timestamp, level, message }) => {
      return `${timestamp} ${level}: ${message}`;
    })
  ),
  transports: [
    new winston.transports.Console()
  ]
});

// 全局异常捕获
process.on('uncaughtException', (err) => {
  logger.error('未捕获异常:', err);
});

// 允许跨域访问
app.use(helmet({
  contentSecurityPolicy: false,
  frameguard: false
}));
app.use(cors());
app.use(express.json({ limit: '50mb' }));

const publicDir = path.resolve(__dirname, '../frontend/public');
const distDir = path.resolve(__dirname, '../frontend/dist');
const publicPath = fs.existsSync(publicDir) ? publicDir : distDir;
app.use(express.static(publicPath));

// MongoDB 连接
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

mongoose.connection.on('connected', () => {
  logger.info('MongoDB 连接成功');
});

mongoose.connection.on('error', (err) => {
  logger.error('MongoDB 连接错误:', err);
});

// MongoDB 数据模型
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, default: 'buyer', enum: ['buyer', 'executor', 'admin'] },
  avatar: String,
  city: String,
  birthday: String,
  notes: String,
  registration_date: { type: Date, default: Date.now },
  initial_username: String,
  updated_date: { type: Date, default: Date.now }
});

const productSchema = new mongoose.Schema({
  name: { type: String, required: true },
  related_name: String,
  description: String,
  original_height: Number,
  original_width: Number,
  original_length: Number,
  parts_count: { type: Number, default: 1 },
  main_image: String,
  additional_images: [String],
  price_options: mongoose.Schema.Types.Mixed,
  is_visible: { type: Boolean, default: true },
  sales_count: { type: Number, default: 0 },
  favorites_count: { type: Number, default: 0 },
  created_date: { type: Date, default: Date.now },
  updated_date: { type: Date, default: Date.now }
});

const orderSchema = new mongoose.Schema({
  user_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  products: mongoose.Schema.Types.Mixed,
  total_price: Number,
  status: { type: String, default: 'создан заказ' },
  notes: String,
  admin_notes: String,
  assigned_executors: [String],
  created_date: { type: Date, default: Date.now },
  updated_date: { type: Date, default: Date.now }
});

const customRequestSchema = new mongoose.Schema({
  user_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  product_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Product' },
  product_name: String,
  model_links: [String],
  additional_name: String,
  required_heights: [String],
  images: [String],
  status: { type: String, default: 'в обработке' },
  admin_notes: String,
  created_date: { type: Date, default: Date.now },
  updated_date: { type: Date, default: Date.now }
});

const chatMessageSchema = new mongoose.Schema({
  from_user_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  to_user_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  message: String,
  created_date: { type: Date, default: Date.now }
});

const settingsSchema = new mongoose.Schema({
  payment_info: String,
  price_coefficient: { type: Number, default: 5.25 },
  discount_rules: mongoose.Schema.Types.Mixed,
  show_discount_on_products: { type: Boolean, default: false }
});

const userFavoriteSchema = new mongoose.Schema({
  user_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  product_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Product', required: true },
  created_date: { type: Date, default: Date.now }
});

const portfolioSchema = new mongoose.Schema({
  user_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  image_path: String,
  created_date: { type: Date, default: Date.now }
});

// 创建模型
const User = mongoose.model('User', userSchema);
const Product = mongoose.model('Product', productSchema);
const Order = mongoose.model('Order', orderSchema);
const CustomRequest = mongoose.model('CustomRequest', customRequestSchema);
const ChatMessage = mongoose.model('ChatMessage', chatMessageSchema);
const Settings = mongoose.model('Settings', settingsSchema);
const UserFavorite = mongoose.model('UserFavorite', userFavoriteSchema);
const Portfolio = mongoose.model('Portfolio', portfolioSchema);

// 文件上传配置 (保持不变)
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = path.join(publicPath, 'uploads');
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    cb(null, `${uuidv4()}-${file.originalname}`);
  }
});

const upload = multer({ 
  storage, 
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('只允许上传图片文件'), false);
    }
  }
});

const avatarStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadsDir = path.join(publicPath, 'uploads', 'avatars');
    if (!fs.existsSync(uploadsDir)) {
      fs.mkdirSync(uploadsDir, { recursive: true });
    }
    cb(null, uploadsDir);
  },
  filename: (req, file, cb) => {
    const fileExtension = path.extname(file.originalname);
    const fileName = `avatar_${Date.now()}_${uuidv4()}${fileExtension}`;
    cb(null, fileName);
  }
});

const avatarUpload = multer({ 
  storage: avatarStorage, 
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('只允许上传图片文件'), false);
    }
  }
});

const portfolioStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    const portfolioDir = path.join(publicPath, 'uploads', 'portfolio');
    if (!fs.existsSync(portfolioDir)) {
      fs.mkdirSync(portfolioDir, { recursive: true });
    }
    cb(null, portfolioDir);
  },
  filename: (req, file, cb) => {
    const fileExtension = path.extname(file.originalname);
    const fileName = `portfolio_${Date.now()}_${uuidv4()}${fileExtension}`;
    cb(null, fileName);
  }
});

const portfolioUpload = multer({ 
  storage: portfolioStorage, 
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('只允许上传图片文件'), false);
    }
  }
});

// 数据库初始化函数
async function initDatabase() {
  try {
    // 检查默认设置
    const settingsExists = await Settings.findOne();
    if (!settingsExists) {
      await Settings.create({
        payment_info: 'Реквизиты для оплаты:\nБанковская карта: 1234 5678 9012 3456\nЯндекс.Деньги: 410011234567890\nQIWI: +79001234567',
        price_coefficient: 5.25,
        discount_rules: [],
        show_discount_on_products: false
      });
      logger.info('默认系统设置创建完成');
    }
    
    // 检查管理员用户
    const adminExists = await User.findOne({ role: 'admin' });
    if (!adminExists) {
      const hashedPassword = bcrypt.hashSync('admin', 10);
      await User.create({
        username: 'admin',
        password: hashedPassword,
        role: 'admin',
        initial_username: 'admin'
      });
      logger.info('默认管理员用户创建完成');
    }
    
    logger.info('数据库初始化完成');
  } catch (error) {
    logger.error('数据库初始化错误:', error.message);
  }
}

// 初始化数据库
initDatabase();

// ==================== API 路由 ====================

// API路由 - 用户管理
app.get('/api/users', async (req, res) => {
  try {
    const users = await User.find({}, { password: 0 })
      .sort({ registration_date: -1 });
    
    logger.info(`获取用户列表: ${users.length} 条记录`);
    res.json(users);
  } catch (error) {
    logger.error('获取用户列表错误:', error.message);
    res.status(500).json({ error: '获取用户列表失败' });
  }
});

app.get('/api/admin/users', async (req, res) => {
  try {
    const { search, role_filter } = req.query;
    let query = {};
    
    if (search) {
      query.$or = [
        { username: { $regex: search, $options: 'i' } }
      ];
      
      // 如果search是数字，也搜索ID
      if (!isNaN(search)) {
        query.$or.push({ _id: search });
      }
    }
    
    if (role_filter) {
      query.role = role_filter;
    }

    const users = await User.find(query, { password: 0 })
      .sort({ registration_date: -1 });
    
    logger.info(`管理员获取用户列表: ${users.length} 条记录`);
    res.json(users);
  } catch (error) {
    logger.error('管理员获取用户列表错误:', error.message);
    res.status(500).json({ error: '获取用户列表失败' });
  }
});

// 用户资料更新
app.put('/api/users/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const updateData = { ...req.body, updated_date: new Date() };
    
    // 移除不应更新的字段
    delete updateData._id;
    delete updateData.registration_date;
    
    // 如果有密码字段，进行加密
    if (updateData.password) {
      updateData.password = bcrypt.hashSync(updateData.password, 10);
    }
    
    const updatedUser = await User.findByIdAndUpdate(
      id, 
      updateData, 
      { new: true, select: '-password' }
    );
    
    if (!updatedUser) {
      return res.status(404).json({ error: 'Пользователь не найден' });
    }
    
    logger.info(`用户资料更新成功: ID ${id}`);
    res.json(updatedUser);
  } catch (error) {
    logger.error('用户资料更新错误:', error.message);
    res.status(500).json({ error: '更新用户资料失败' });
  }
});

// 用户删除
app.delete('/api/users/:id', async (req, res) => {
  try {
    const { id } = req.params;
    
    const user = await User.findById(id);
    if (!user) {
      return res.status(404).json({ error: 'Пользователь не найден' });
    }
    
    // 防止删除管理员账户
    if (user.role === 'admin') {
      return res.status(403).json({ error: 'Невозможно удалить администратора' });
    }
    
    await User.findByIdAndDelete(id);
    
    logger.info(`用户删除成功: ID ${id}`);
    res.json({ message: 'Пользователь успешно удален' });
  } catch (error) {
    logger.error('用户删除错误:', error.message);
    res.status(500).json({ error: 'Ошибка удаления пользователя' });
  }
});

// 头像上传
app.post('/api/upload/avatar', avatarUpload.single('avatar'), async (req, res) => {
  try {
    const { user_id } = req.body;
    
    if (!req.file) {
      return res.status(400).json({ error: 'Файл аватара не найден' });
    }
    
    if (!user_id) {
      return res.status(400).json({ error: 'ID пользователя обязателен' });
    }

    const avatarPath = `/uploads/avatars/${req.file.filename}`;
    
    const updatedUser = await User.findByIdAndUpdate(
      user_id,
      { avatar: avatarPath },
      { new: true, select: '-password' }
    );
    
    if (!updatedUser) {
      return res.status(404).json({ error: 'Пользователь не найден' });
    }
    
    logger.info(`头像上传成功: 用户 ${user_id}, 文件 ${req.file.filename}`);
    res.json({ 
      success: true,
      avatar_path: avatarPath,
      message: 'Аватар успешно загружен'
    });
  } catch (error) {
    logger.error('头像上传错误:', error.message);
    res.status(500).json({ error: 'Ошибка загрузки аватара' });
  }
});

// 获取用户信息
app.get('/api/users/:id', async (req, res) => {
  try {
    const user = await User.findById(req.params.id, { password: 0 });
    
    if (!user) {
      return res.status(404).json({ error: 'Пользователь не найден' });
    }
    
    logger.info(`获取用户信息成功: ID ${req.params.id}`);
    res.json(user);
  } catch (error) {
    logger.error('获取用户信息错误:', error.message);
    res.status(500).json({ error: '获取用户信息失败' });
  }
});

// API路由 - 作品集管理
app.get('/api/portfolio/:user_id', async (req, res) => {
  try {
    const { user_id } = req.params;
    
    if (!user_id) {
      return res.status(400).json({ error: 'Некорректный ID пользователя' });
    }

    // 检查用户是否存在且是执行者
    const user = await User.findById(user_id);
    if (!user) {
      return res.status(404).json({ error: 'Пользователь не найден' });
    }

    if (user.role !== 'executor') {
      return res.status(403).json({ error: 'Портфолио доступно только для исполнителей' });
    }

    const portfolio = await Portfolio.find({ user_id })
      .sort({ created_date: -1 });
    
    logger.info(`获取作品集成功: 用户 ${user_id}, ${portfolio.length} 张图片`);
    res.json(portfolio);
  } catch (error) {
    logger.error('获取作品集错误:', error.message);
    res.status(500).json({ error: 'Ошибка при загрузке портфолио' });
  }
});

app.post('/api/portfolio', portfolioUpload.array('images', 20), async (req, res) => {
  try {
    const { user_id } = req.body;
    
    if (!user_id) {
      return res.status(400).json({ error: 'Некорректный ID пользователя' });
    }

    if (!req.files || req.files.length === 0) {
      return res.status(400).json({ error: 'Не выбраны файлы для загрузки' });
    }

    // 检查用户权限
    const user = await User.findById(user_id);
    if (!user || user.role !== 'executor') {
      return res.status(403).json({ error: 'Только исполнители могут загружать работы в портфолио' });
    }

    // 检查当前数量
    const currentPortfolioCount = await Portfolio.countDocuments({ user_id });
    if (currentPortfolioCount + req.files.length > 20) {
      return res.status(400).json({ error: 'Максимум 20 изображений в портфолио' });
    }

    // 创建作品集记录
    const portfolioEntries = req.files.map(file => ({
      user_id,
      image_path: `/uploads/portfolio/${file.filename}`
    }));

    const createdEntries = await Portfolio.insertMany(portfolioEntries);
    
    logger.info(`作品集图片上传成功: 用户 ${user_id}, ${req.files.length} 张图片`);
    res.status(201).json({
      success: true,
      message: 'Изображения успешно загружены',
      uploaded: createdEntries.length,
      images: createdEntries
    });
  } catch (error) {
    logger.error('作品集图片上传错误:', error.message);
    res.status(500).json({ error: 'Ошибка при загрузке изображений' });
  }
});

app.delete('/api/portfolio/:image_id', async (req, res) => {
  try {
    const { image_id } = req.params;
    
    if (!image_id) {
      return res.status(400).json({ error: 'Некорректный ID изображения' });
    }

    const portfolioItem = await Portfolio.findById(image_id);
    if (!portfolioItem) {
      return res.status(404).json({ error: 'Изображение не найдено' });
    }

    // 删除文件
    const imagePath = path.join(publicPath, portfolioItem.image_path);
    if (fs.existsSync(imagePath)) {
      try {
        fs.unlinkSync(imagePath);
        logger.info(`删除文件成功: ${imagePath}`);
      } catch (fileError) {
        logger.warn(`删除文件失败: ${imagePath}, 错误: ${fileError.message}`);
      }
    }

    // 从数据库删除
    await Portfolio.findByIdAndDelete(image_id);
    
    logger.info(`作品集图片删除成功: ID ${image_id}`);
    res.json({
      success: true,
      message: 'Изображение успешно удалено'
    });
  } catch (error) {
    logger.error('作品集图片删除错误:', error.message);
    res.status(500).json({ error: 'Ошибка при удалении изображения' });
  }
});

// API路由 - 订单管理
app.get('/api/orders', async (req, res) => {
  try {
    const { user_id, role, admin, search, status } = req.query;
    let query = {};
    
    if (!admin && user_id) {
      query.user_id = user_id;
    }
    
    if (search) {
      query._id = search;
    }
    
    if (status) {
      query.status = status;
    }

    const orders = await Order.find(query)
      .populate('user_id', 'username')
      .sort({ created_date: -1 });

    logger.info(`获取订单列表: ${orders.length} 条记录`);
    res.json(orders);
  } catch (error) {
    logger.error('获取订单列表错误:', error.message);
    res.status(500).json({ error: '获取订单列表失败' });
  }
});

app.post('/api/orders', async (req, res) => {
  try {
    const { user_id, products, total_price, notes } = req.body;
    
    if (!user_id || !products || !total_price) {
      return res.status(400).json({ error: '缺少必要参数' });
    }

    const order = await Order.create({
      user_id,
      products,
      total_price,
      notes: notes || '',
      status: 'создан заказ'
    });
    
    await order.populate('user_id', 'username');
    
    logger.info(`创建订单: ID ${order._id}, 用户 ${user_id}`);
    res.status(201).json(order);
  } catch (error) {
    logger.error('创建订单错误:', error.message);
    res.status(500).json({ error: '创建订单失败' });
  }
});

// 订单状态更新
app.put('/api/orders/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const updateData = { ...req.body, updated_date: new Date() };
    
    const updatedOrder = await Order.findByIdAndUpdate(
      id,
      updateData,
      { new: true }
    ).populate('user_id', 'username');
    
    if (!updatedOrder) {
      return res.status(404).json({ error: 'Заказ не найден' });
    }
    
    logger.info(`订单状态更新成功: ID ${id}`);
    res.json(updatedOrder);
  } catch (error) {
    logger.error('订单状态更新错误:', error.message);
    res.status(500).json({ error: '更新订单状态失败' });
  }
});

// API路由 - 系统设置
app.get('/api/settings', async (req, res) => {
  try {
    let settings = await Settings.findOne();
    
    if (!settings) {
      settings = await Settings.create({
        payment_info: 'Реквизиты для оплаты:\nБанковская карта: 1234 5678 9012 3456\nЯндекс.Деньги: 410011234567890\nQIWI: +79001234567',
        price_coefficient: 5.25,
        discount_rules: [],
        show_discount_on_products: false
      });
    }
    
    logger.info('获取系统设置成功');
    res.json(settings);
  } catch (error) {
    logger.error('获取系统设置错误:', error.message);
    res.status(500).json({ error: '获取系统设置失败' });
  }
});

app.put('/api/settings', async (req, res) => {
  try {
    const { payment_info, price_coefficient, discount_rules, show_discount_on_products } = req.body;
    
    let settings = await Settings.findOne();
    
    const updateData = {
      payment_info: payment_info || '',
      price_coefficient: parseFloat(price_coefficient) || 5.25,
      discount_rules: discount_rules || [],
      show_discount_on_products: Boolean(show_discount_on_products)
    };
    
    if (settings) {
      settings = await Settings.findOneAndUpdate({}, updateData, { new: true });
    } else {
      settings = await Settings.create(updateData);
    }
    
    logger.info('更新系统设置成功');
    res.json({ message: '设置更新成功', settings });
  } catch (error) {
    logger.error('更新系统设置错误:', error.message);
    res.status(500).json({ error: '更新系统设置失败' });
  }
});

// API路由 - 商品管理
app.get('/api/products', async (req, res) => {
  try {
    const { search, filter, admin } = req.query;
    let query = {};
    
    if (!admin) query.is_visible = true;
    
    if (search) {
      if (filter === 'description') {
        query.description = { $regex: search, $options: 'i' };
      } else if (filter === 'id') {
        query._id = search;
      } else {
        query.name = { $regex: search, $options: 'i' };
      }
    }

    const products = await Product.find(query)
      .sort({ created_date: -1 });

    const settings = await Settings.findOne();
    const priceCoefficient = settings ? settings.price_coefficient : 5.25;

    const processedProducts = products.map(product => {
      const productObj = product.toObject();
      
      if (productObj.price_options && Array.isArray(productObj.price_options)) {
        productObj.price_options = productObj.price_options.map(option => {
          const processedOption = { ...option };
          
          if (admin !== 'true') {
            delete processedOption.resin_ml;
          }
          
          if (processedOption.price) {
            processedOption.price = Math.round((processedOption.price / 5.25) * priceCoefficient);
          }
          
          return processedOption;
        });
      }
      
      return productObj;
    });
    
    logger.info(`获取商品列表: ${processedProducts.length} 条记录`);
    res.json(processedProducts);
  } catch (error) {
    logger.error('获取商品列表错误:', error.message);
    res.status(500).json({ error: '获取商品列表失败' });
  }
});

// 商品添加
app.post('/api/products', upload.fields([
  { name: 'main_image', maxCount: 1 },
  { name: 'additional_images', maxCount: 4 }
]), async (req, res) => {
  try {
    const { name, related_name, description, original_height, original_width, original_length, parts_count, price_options, is_visible } = req.body;
    
    if (!name || !name.trim()) {
      return res.status(400).json({ error: 'Название товара обязательно' });
    }
    
    if (!price_options) {
      return res.status(400).json({ error: 'Варианты цен обязательны' });
    }

    // 处理价格选项
    let parsedPriceOptions;
    try {
      parsedPriceOptions = JSON.parse(price_options);
      if (!Array.isArray(parsedPriceOptions) || parsedPriceOptions.length === 0) {
        return res.status(400).json({ error: 'Должен быть хотя бы один вариант цены' });
      }
    } catch (e) {
      return res.status(400).json({ error: 'Неверный формат вариантов цен' });
    }

    // 处理主图片
    let mainImagePath = null;
    if (req.files && req.files.main_image && req.files.main_image[0]) {
      mainImagePath = `/uploads/${req.files.main_image[0].filename}`;
    }

    // 处理附加图片
    let additionalImages = [];
    if (req.files && req.files.additional_images) {
      additionalImages = req.files.additional_images.map(file => `/uploads/${file.filename}`);
    }

    const productData = {
      name: name.trim(),
      related_name: related_name ? related_name.trim() : null,
      description: description ? description.trim() : null,
      original_height: original_height ? parseFloat(original_height) : null,
      original_width: original_width ? parseFloat(original_width) : null,
      original_length: original_length ? parseFloat(original_length) : null,
      parts_count: parts_count ? parseInt(parts_count) : 1,
      main_image: mainImagePath,
      additional_images: additionalImages,
      price_options: parsedPriceOptions,
      is_visible: is_visible !== undefined ? Boolean(is_visible) : true
    };

    const product = await Product.create(productData);
    
    logger.info(`商品创建成功: ID ${product._id}, 名称 ${product.name}`);
    res.status(201).json(product);
  } catch (error) {
    logger.error('创建商品错误:', error.message);
    res.status(500).json({ error: '创建商品失败' });
  }
});

// 商品删除
app.delete('/api/products/:id', async (req, res) => {
  try {
    const { id } = req.params;
    
    if (!id) {
      return res.status(400).json({ error: 'Некорректный ID товара' });
    }

    const product = await Product.findById(id);
    if (!product) {
      return res.status(404).json({ error: 'Товар не найден' });
    }

    // 删除商品相关的收藏记录
    await UserFavorite.deleteMany({ product_id: id });

    // 删除商品
    await Product.findByIdAndDelete(id);
    
    logger.info(`商品删除成功: ID ${id}`);
    res.json({ 
      success: true,
      message: 'Товар успешно удален'
    });
  } catch (error) {
    logger.error('商品删除错误:', error.message);
    res.status(500).json({ error: 'Ошибка при удалении товара' });
  }
});

// API路由 - 收藏功能
app.post('/api/favorites/toggle', async (req, res) => {
  try {
    const { user_id, product_id } = req.body;
    
    if (!user_id || !product_id) {
      return res.status(400).json({ error: '缺少必要参数' });
    }

    const existingFavorite = await UserFavorite.findOne({
      user_id, product_id
    });

    let is_favorite = false;

    if (existingFavorite) {
      await UserFavorite.findByIdAndDelete(existingFavorite._id);
      
      await Product.findByIdAndUpdate(product_id, {
        $inc: { favorites_count: -1 }
      });
      
      is_favorite = false;
    } else {
      await UserFavorite.create({ user_id, product_id });
      
      await Product.findByIdAndUpdate(product_id, {
        $inc: { favorites_count: 1 }
      });
      
      is_favorite = true;
    }
    
    logger.info(`用户 ${user_id} ${is_favorite ? '添加' : '取消'} 商品 ${product_id} 收藏`);
    res.json({ is_favorite, message: is_favorite ? '已添加到收藏' : '已取消收藏' });
  } catch (error) {
    logger.error('切换收藏状态错误:', error.message);
    res.status(500).json({ error: '操作失败' });
  }
});

app.get('/api/favorites/:user_id', async (req, res) => {
  try {
    const { user_id } = req.params;
    
    const favorites = await UserFavorite.find({ user_id })
      .populate('product_id');

    const favoriteProducts = favorites.map(fav => fav.product_id);
    
    logger.info(`获取用户 ${user_id} 的收藏列表: ${favoriteProducts.length} 条记录`);
    res.json(favoriteProducts);
  } catch (error) {
    logger.error('获取收藏列表错误:', error.message);
    res.status(500).json({ error: '获取收藏列表失败' });
  }
});

// API路由 - 聊天功能
app.get('/api/chat/messages', async (req, res) => {
  try {
    const { user_id, with_user_id, limit = 100 } = req.query;
    
    if (!user_id || !with_user_id) {
      return res.status(400).json({ error: '缺少必要参数' });
    }

    const messages = await ChatMessage.find({
      $or: [
        { from_user_id: user_id, to_user_id: with_user_id },
        { from_user_id: with_user_id, to_user_id: user_id }
      ]
    })
    .populate('from_user_id', 'username')
    .sort({ created_date: -1 })
    .limit(parseInt(limit));

    const processedMessages = messages.map(msg => {
      const msgData = msg.toObject();
      return {
        id: msgData._id,
        content: msgData.message,
        sender_id: msgData.from_user_id._id,
        receiver_id: msgData.to_user_id,
        sender_name: msgData.from_user_id.username,
        created_at: msgData.created_date
      };
    }).reverse();
    
    logger.info(`获取聊天消息: 用户 ${user_id} 与 ${with_user_id}, ${processedMessages.length} 条消息`);
    res.json(processedMessages);
  } catch (error) {
    logger.error('获取聊天消息错误:', error.message);
    res.status(500).json({ error: '获取聊天消息失败' });
  }
});

app.post('/api/chat', async (req, res) => {
  try {
    const { from_user_id, to_user_id, message } = req.body;
    
    if (!from_user_id || !to_user_id || !message) {
      return res.status(400).json({ error: '缺少必要参数' });
    }

    const chatMessage = await ChatMessage.create({
      from_user_id,
      to_user_id,
      message: message.trim()
    });
    
    await chatMessage.populate('from_user_id', 'username');
    
    const responseData = {
      id: chatMessage._id,
      message: chatMessage.message,
      from_user_id: chatMessage.from_user_id._id,
      to_user_id: chatMessage.to_user_id,
      from_username: chatMessage.from_user_id.username,
      created_date: chatMessage.created_date
    };
    
    logger.info(`发送聊天消息: 从用户 ${from_user_id} 到用户 ${to_user_id}`);
    res.status(201).json({ data: responseData });
  } catch (error) {
    logger.error('发送聊天消息错误:', error.message);
    res.status(500).json({ error: '发送消息失败' });
  }
});

// 邮件广播API
app.post('/api/chat/broadcast', async (req, res) => {
  try {
    const { message, from_user_id } = req.body;
    
    if (!message || !message.trim()) {
      return res.status(400).json({ error: 'Сообщение не может быть пустым' });
    }
    
    if (!from_user_id) {
      return res.status(400).json({ error: 'ID отправителя обязателен' });
    }

    // 获取所有用户（除了发送者）
    const users = await User.find({
      _id: { $ne: from_user_id }
    }, 'id username');

    if (users.length === 0) {
      return res.status(404).json({ error: 'Нет пользователей для рассылки' });
    }

    // 创建广播消息
    const broadcastMessages = users.map(user => ({
      from_user_id,
      to_user_id: user._id,
      message: message.trim()
    }));

    await ChatMessage.insertMany(broadcastMessages);
    
    logger.info(`广播消息发送成功: 从用户 ${from_user_id} 到 ${users.length} 个用户`);
    res.status(201).json({
      message: 'Рассылка отправлена успешно',
      count: broadcastMessages.length,
      recipients: users.length
    });
  } catch (error) {
    logger.error('广播消息错误:', error.message);
    res.status(500).json({ error: 'Ошибка при отправке рассылки' });
  }
});

// API路由 - 用户注册和登录
app.post('/api/register', async (req, res) => {
  try {
    const { username, password, role } = req.body;
    
    if (!username || !username.trim()) {
      return res.status(400).json({ error: 'Имя пользователя обязательно' });
    }
    
    if (!password || password.length < 6) {
      return res.status(400).json({ error: 'Пароль должен содержать минимум 6 символов' });
    }
    
    const cleanUsername = username.trim();
    
    if (cleanUsername.length < 3 || cleanUsername.length > 50) {
      return res.status(400).json({ error: 'Имя пользователя должно содержать от 3 до 50 символов' });
    }

    const existingUser = await User.findOne({ username: cleanUsername });
    if (existingUser) {
      return res.status(400).json({ error: 'Пользователь с таким именем уже существует' });
    }

    const userCount = await User.countDocuments();
    const isFirstUser = userCount === 0;

    const hashedPassword = bcrypt.hashSync(password, 10);
    
    const userRole = isFirstUser ? 'admin' : (role && ['buyer', 'executor'].includes(role) ? role : 'buyer');
    
    const userData = {
      username: cleanUsername,
      password: hashedPassword,
      role: userRole,
      initial_username: cleanUsername
    };

    const user = await User.create(userData);
    
    const userResponse = {
      id: user._id,
      username: user.username,
      role: user.role,
      registration_date: user.registration_date
    };
    
    logger.info(`用户注册成功: ID ${user._id}, username: ${user.username}, role: ${user.role}${isFirstUser ? ' (首个管理员)' : ''}`);
    
    res.status(201).json({ 
      message: `Пользователь успешно зарегистрирован${isFirstUser ? ' как администратор' : ''}`,
      user: userResponse
    });
    
  } catch (error) {
    logger.error('用户注册错误:', error.message);
    
    if (error.code === 11000) {
      return res.status(400).json({ error: 'Пользователь с таким именем уже существует' });
    }
    
    res.status(500).json({ error: 'Произошла ошибка при регистрации пользователя' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !username.trim() || !password) {
      return res.status(400).json({ error: 'Имя пользователя и пароль обязательны' });
    }

    const user = await User.findOne({ username: username.trim() });

    if (!user) {
      return res.status(404).json({ error: 'Пользователь не найден' });
    }

    const passwordMatch = bcrypt.compareSync(password, user.password);
    if (!passwordMatch) {
      return res.status(401).json({ error: 'Неверный пароль' });
    }

    const userResponse = user.toObject();
    delete userResponse.password;
    
    logger.info(`用户登录成功: ${user.username} (ID: ${user._id})`);
    res.status(200).json({
      message: 'Вход выполнен успешно',
      user: userResponse
    });

  } catch (error) {
    logger.error('登录错误:', error.message);
    res.status(500).json({ error: 'Ошибка сервера при входе' });
  }
});

// API路由 - 自定义请求管理
app.get('/api/custom-requests', async (req, res) => {
  try {
    const { user_id, role } = req.query;
    let query = {};
    
    if (role !== 'admin' && user_id) {
      query.user_id = user_id;
    }

    const requests = await CustomRequest.find(query)
      .populate('user_id', 'username')
      .sort({ created_date: -1 });
    
    logger.info(`获取自定义请求列表: ${requests.length} 条记录`);
    res.json(requests);
  } catch (error) {
    logger.error('获取自定义请求列表错误:', error.message);
    res.status(500).json({ error: '获取请求列表失败' });
  }
});

app.post('/api/custom-requests', upload.array('images', 3), async (req, res) => {
  try {
    const { user_id, product_name, additional_name, product_id, model_links, required_heights } = req.body;
    
    if (!user_id || !product_name || !product_name.trim()) {
      return res.status(400).json({ error: '缺少必要参数' });
    }

    // 处理上传的图片
    let images = [];
    if (req.files && req.files.length > 0) {
      images = req.files.map(file => `/uploads/${file.filename}`);
    }

    const requestData = {
      user_id,
      product_name: product_name.trim(),
      additional_name: additional_name ? additional_name.trim() : null,
      product_id: product_id || null,
      model_links: model_links ? model_links.split(',') : [],
      required_heights: required_heights ? required_heights.split(',') : [],
      images,
      status: 'в обработке'
    };

    const customRequest = await CustomRequest.create(requestData);
    await customRequest.populate('user_id', 'username');
    
    logger.info(`创建自定义请求成功: ID ${customRequest._id}, 用户 ${user_id}`);
    res.status(201).json(customRequest);
  } catch (error) {
    logger.error('创建自定义请求错误:', error.message);
    res.status(500).json({ error: '创建请求失败' });
  }
});

// 测量申请状态更新
app.put('/api/custom-requests/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const updateData = { ...req.body, updated_date: new Date() };
    
    if (!id) {
      return res.status(400).json({ error: 'Некорректный ID заявки' });
    }

    const customRequest = await CustomRequest.findByIdAndUpdate(
      id,
      updateData,
      { new: true }
    ).populate('user_id', 'username');
    
    if (!customRequest) {
      return res.status(404).json({ error: 'Заявка не найдена' });
    }
    
    logger.info(`测量申请状态更新成功: ID ${id}`);
    res.json(customRequest);
  } catch (error) {
    logger.error('测量申请状态更新错误:', error.message);
    res.status(500).json({ error: 'Ошибка при обновлении статуса заявки' });
  }
});

// 异常日志收集
app.get('/logs', (req, res) => {
  res.json({ message: '日志功能正常运行' });
});

// 处理前端路由
app.get('*', (req, res) => {
  try {
    const filePath = path.join(publicPath, req.path);
    if (fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
      res.sendFile(filePath);
    } else {
      res.sendFile(path.join(publicPath, 'index.html'));
    }
  } catch (error) {
    logger.error('路由处理错误:', error.message);
    res.status(404).send('页面不存在');
  }
});

// 处理404错误
app.use((req, res) => {
  res.status(404).json({ error: '接口不存在' });
});

// 全局错误处理
app.use((err, req, res, next) => {
  logger.error('全局错误:', err.message);
  res.status(500).json({ error: '服务器内部错误' });
});
