// web/static/js/dashboard.js

// Hàm format số
function formatNumber(num) {
    return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
}

// Hàm format ngày giờ
function formatDateTime(dateString) {
    const date = new Date(dateString);
    return date.toLocaleString('vi-VN');
}

// Hàm lấy màu theo mức độ rủi ro
function getRiskColor(riskLevel) {
    switch(riskLevel) {
        case 'Rất cao': return '#dc3545';
        case 'Cao': return '#fd7e14';
        case 'Trung bình': return '#ffc107';
        default: return '#28a745';
    }
}

// Hàm tạo badge
function createBadge(text, type) {
    const colors = {
        success: 'bg-success',
        warning: 'bg-warning',
        danger: 'bg-danger',
        info: 'bg-info'
    };
    return `<span class="badge ${colors[type] || 'bg-secondary'}">${text}</span>`;
}

// Export các hàm
window.malwareUtils = {
    formatNumber,
    formatDateTime,
    getRiskColor,
    createBadge
};