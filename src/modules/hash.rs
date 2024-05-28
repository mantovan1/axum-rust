use pwhash::bcrypt;

pub fn hash(password: &str) -> Result<String, pwhash::error::Error> {
    bcrypt::hash(password)
}