import mongoose from 'mongoose'

const passwordResetAttemptSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    lowercase: true,
    trim: true,
    unique: true,
    index: true
  },
  count: {
    type: Number,
    default: 0
  },
  windowStart: {
    type: Date,
    default: Date.now
  },
  lastSentAt: {
    type: Date,
    default: null
  }
})

const PasswordResetAttempt = mongoose.model('PasswordResetAttempt', passwordResetAttemptSchema)

export default PasswordResetAttempt
