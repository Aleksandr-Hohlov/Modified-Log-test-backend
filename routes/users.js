const router = require('express').Router();
const auth = require('../middlewares/auth');
const {
  userIdValidation,
  updateUserValidation,
  updateAvatarValidation,
} = require('../middlewares/validation');

const {
  getAllUsers,
  getUserById,
  updateUserInfo,
  updateAvatar,
  getUser,
} = require('../controllers/users');

router.use(auth);
router.get('/', getAllUsers);
router.get('/me', getUser);
router.get('/:userId', userIdValidation, getUserById);
router.patch('/me', updateUserValidation, updateUserInfo);
router.patch('/me/avatar', updateAvatarValidation, updateAvatar);

module.exports = router;
